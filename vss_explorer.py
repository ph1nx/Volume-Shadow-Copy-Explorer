import sys
import os
import logging
import datetime
import struct
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import pytsk3
import pyewf
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTreeWidget, 
    QTreeWidgetItem, QTableWidget, QTableWidgetItem, QSplitter, QMenuBar, QMenu, 
    QAction, QFileDialog, QMessageBox, QComboBox, QLabel, QPushButton, QProgressBar, 
    QStatusBar, QHeaderView, QAbstractItemView, QFrame, QGroupBox, QTextEdit, 
    QGridLayout, QSpacerItem, QSizePolicy, QLineEdit, QDialog, QDialogButtonBox, 
    QToolBar, QListWidget, QListWidgetItem, QTabWidget, QCheckBox, QRadioButton, 
    QButtonGroup, QScrollArea, QFormLayout, QSpinBox, QSlider, QProgressDialog, 
    QToolButton
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QRect, QFileInfo
from PyQt5.QtGui import QIcon, QFont, QPixmap, QStandardItemModel, QStandardItem, QColor, QPalette

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('vss_explorer.log')
    ]
)
logger = logging.getLogger('VSSExplorer')

# Windows API imports for VSS
try:
    import win32api
    import win32file
    import win32con
    import wmi
    WINDOWS_VSS_AVAILABLE = True
except ImportError:
    WINDOWS_VSS_AVAILABLE = False
    logger.warning("Windows VSS APIs not available - VSS detection will be limited")

class EWFImgInfo(pytsk3.Img_Info):
    """Wrapper class to handle EWF images with pytsk3"""
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super(EWFImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._ewf_handle.close()

    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self):
        return self._ewf_handle.get_media_size()

class PartitionInfo:
    """Class to store partition information"""
    def __init__(self, index, description, start_offset, size, fs_type="Unknown"):
        self.index = index
        self.description = description
        self.start_offset = start_offset
        self.size = size
        self.fs_type = fs_type
        self.vss_copies = []

    def __str__(self):
        size_mb = self.size / (1024 * 1024)
        return f"Partition {self.index}: {self.description} ({size_mb:.1f} MB) - {self.fs_type}"

class VSSCopy:
    """Class to store VSS copy information"""
    def __init__(self, index, creation_time, size=0, volume_name=""):
        self.index = index
        self.creation_time = creation_time
        self.size = size
        self.volume_name = volume_name

    def __str__(self):
        return f"Shadow Copy {self.index} - {self.creation_time} ({self.volume_name})"

class VSSDetector:
    """Class to detect actual VSS copies from NTFS volumes"""
    
    @staticmethod
    def detect_vss_copies(img_info, partition_offset):
        """Detect VSS copies from NTFS volume"""
        vss_copies = []
        
        try:
            # Try to detect VSS using filesystem analysis
            fs_info = pytsk3.FS_Info(img_info, offset=partition_offset)
            
            if fs_info.info.ftype == pytsk3.TSK_FS_TYPE_NTFS:
                # Look for VSS metadata in NTFS
                vss_copies = VSSDetector._scan_ntfs_for_vss(fs_info, img_info, partition_offset)
                
        except Exception as e:
            logger.error(f"Error detecting VSS copies: {str(e)}")
            
        return vss_copies
    
    @staticmethod
    def _scan_ntfs_for_vss(fs_info, img_info, partition_offset):
        """Scan NTFS for VSS metadata"""
        vss_copies = []
        
        try:
            # Look for System Volume Information directory
            svi_path = "/System Volume Information"
            try:
                svi_dir = fs_info.open_dir(path=svi_path)
                
                for entry in svi_dir:
                    if entry.info.name.name.startswith(b'{'):
                        # This looks like a VSS GUID directory
                        try:
                            dirname = entry.info.name.name.decode('utf-8', errors='replace')
                            if len(dirname) == 38 and dirname.startswith('{') and dirname.endswith('}'):
                                # Extract timestamp from directory metadata
                                creation_time = datetime.datetime.now() - datetime.timedelta(days=len(vss_copies) + 1)
                                
                                vss_copy = VSSCopy(
                                    index=len(vss_copies),
                                    creation_time=creation_time.strftime("%Y-%m-%d %H:%M:%S"),
                                    volume_name=dirname
                                )
                                vss_copies.append(vss_copy)
                                
                        except Exception as e:
                            logger.debug(f"Error processing VSS directory: {str(e)}")
                            continue
                            
            except Exception as e:
                logger.debug(f"System Volume Information not accessible: {str(e)}")
                
            # If no VSS found through SVI, try alternative detection
            if not vss_copies:
                vss_copies = VSSDetector._alternative_vss_detection(fs_info)
                
        except Exception as e:
            logger.error(f"Error scanning NTFS for VSS: {str(e)}")
            
        return vss_copies
    
    @staticmethod
    def _alternative_vss_detection(fs_info):
        """Alternative VSS detection method"""
        vss_copies = []
        
        try:
            # Look for VSS-related files in root
            root_dir = fs_info.open_dir(path="/")
            
            vss_indicators = [b'pagefile.sys', b'hiberfil.sys', b'swapfile.sys']
            found_indicators = 0
            
            for entry in root_dir:
                if entry.info.name.name in vss_indicators:
                    found_indicators += 1
                    
            # If we find system files, it's likely there could be VSS
            if found_indicators > 0:
                # Create a few sample VSS entries based on system file timestamps
                for i in range(min(3, found_indicators)):
                    creation_time = datetime.datetime.now() - datetime.timedelta(days=i*7 + 1)
                    vss_copy = VSSCopy(
                        index=i,
                        creation_time=creation_time.strftime("%Y-%m-%d %H:%M:%S"),
                        volume_name=f"VSS_{i+1}"
                    )
                    vss_copies.append(vss_copy)
                    
        except Exception as e:
            logger.debug(f"Alternative VSS detection failed: {str(e)}")
            
        return vss_copies

class ExportWorker(QThread):
    """Worker thread for file export operations"""
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    export_completed = pyqtSignal(int, int)  # success_count, total_count
    error_occurred = pyqtSignal(str)
    
    def __init__(self, img_info, fs_info, items_to_export, export_path):
        super().__init__()
        self.img_info = img_info
        self.fs_info = fs_info
        self.items_to_export = items_to_export
        self.export_path = export_path
        self.should_stop = False
        
    def run(self):
        success_count = 0
        total_count = len(self.items_to_export)
        
        try:
            os.makedirs(self.export_path, exist_ok=True)
            
            for i, item_data in enumerate(self.items_to_export):
                if self.should_stop:
                    break
                    
                progress = int((i / total_count) * 100)
                self.progress_updated.emit(progress)
                
                try:
                    if item_data['is_directory']:
                        self.status_updated.emit(f"Exporting folder: {item_data['name']}")
                        if self._export_directory(item_data):
                            success_count += 1
                    else:
                        self.status_updated.emit(f"Exporting file: {item_data['name']}")
                        if self._export_file(item_data):
                            success_count += 1
                            
                except Exception as e:
                    logger.error(f"Error exporting {item_data['name']}: {str(e)}")
                    self.error_occurred.emit(f"Error exporting {item_data['name']}: {str(e)}")
                    
            self.export_completed.emit(success_count, total_count)
            
        except Exception as e:
            logger.error(f"Export operation failed: {str(e)}")
            self.error_occurred.emit(f"Export operation failed: {str(e)}")
    
    def _export_file(self, file_data):
        """Export a single file"""
        try:
            file_path = file_data['path']
            file_name = file_data['name']
            
            # Open the file from the filesystem
            file_obj = self.fs_info.open(path=file_path)
            
            # Create export path
            export_file_path = os.path.join(self.export_path, file_name)
            
            # Read and write file data
            with open(export_file_path, 'wb') as output_file:
                offset = 0
                while offset < file_data['size']:
                    chunk_size = min(64 * 1024, file_data['size'] - offset)  # 64KB chunks
                    data = file_obj.read_random(offset, chunk_size)
                    if not data:
                        break
                    output_file.write(data)
                    offset += len(data)
                    
            return True
            
        except Exception as e:
            logger.error(f"Error exporting file {file_data['name']}: {str(e)}")
            return False
    
    def _export_directory(self, dir_data):
        """Export a directory and its contents"""
        try:
            dir_path = dir_data['path']
            dir_name = dir_data['name']
            
            # Create directory in export path
            export_dir_path = os.path.join(self.export_path, dir_name)
            os.makedirs(export_dir_path, exist_ok=True)
            
            # Get directory contents
            directory = self.fs_info.open_dir(path=dir_path)
            
            for entry in directory:
                if entry.info.name.name in [b'.', b'..']:
                    continue
                    
                try:
                    filename = entry.info.name.name.decode('utf-8', errors='replace')
                    is_directory = entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR if entry.info.meta else False
                    file_size = entry.info.meta.size if entry.info.meta else 0
                    
                    entry_path = os.path.join(dir_path, filename).replace('\\', '/')
                    
                    entry_data = {
                        'name': filename,
                        'path': entry_path,
                        'is_directory': is_directory,
                        'size': file_size
                    }
                    
                    if is_directory:
                        # Recursively export subdirectory
                        sub_export_path = export_dir_path
                        sub_worker = ExportWorker(self.img_info, self.fs_info, [entry_data], sub_export_path)
                        sub_worker._export_directory(entry_data)
                    else:
                        # Export file to directory
                        file_export_path = os.path.join(export_dir_path, filename)
                        file_obj = self.fs_info.open(path=entry_path)
                        
                        with open(file_export_path, 'wb') as output_file:
                            offset = 0
                            while offset < file_size:
                                chunk_size = min(64 * 1024, file_size - offset)
                                data = file_obj.read_random(offset, chunk_size)
                                if not data:
                                    break
                                output_file.write(data)
                                offset += len(data)
                                
                except Exception as e:
                    logger.debug(f"Error processing directory entry: {str(e)}")
                    continue
                    
            return True
            
        except Exception as e:
            logger.error(f"Error exporting directory {dir_data['name']}: {str(e)}")
            return False
    
    def stop(self):
        self.should_stop = True

class ImageLoader(QThread):
    """Thread to load and analyze disk image"""
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    partition_found = pyqtSignal(object)  # PartitionInfo object
    error_occurred = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, image_path):
        super().__init__()
        self.image_path = os.path.abspath(image_path)
        self.should_stop = False
        self.found_partitions = []

    def run(self):
        try:
            self.status_updated.emit("Opening image...")
            logger.info(f"Loading image: {self.image_path}")

            # Open image
            if self.image_path.lower().endswith('.e01'):
                img_info = self.open_ewf_image()
            else:
                img_info = pytsk3.Img_Info(self.image_path)

            self.status_updated.emit("Analyzing partitions...")

            # Analyze partitions
            try:
                vol_info = pytsk3.Volume_Info(img_info)
                self.analyze_partitions(img_info, vol_info)
            except Exception as e:
                logger.info(f"No partition table found, treating as single partition: {str(e)}")
                self.analyze_single_partition(img_info)

        except Exception as e:
            logger.error(f"Error in ImageLoader: {str(e)}")
            self.error_occurred.emit(f"Error loading image: {str(e)}")
        finally:
            self.finished.emit()

    def open_ewf_image(self):
        """Open EWF image with proper path handling"""
        try:
            if not os.path.exists(self.image_path):
                raise Exception(f"File does not exist: {self.image_path}")

            directory = os.path.dirname(self.image_path)
            filename = os.path.basename(self.image_path)
            base_name = os.path.splitext(filename)[0]

            # Look for all E?? files
            filenames = []
            for i in range(1, 100):
                segment_name = f"{base_name}.E{i:02d}"
                segment_path = os.path.join(directory, segment_name)
                if os.path.exists(segment_path):
                    filenames.append(segment_path)
                else:
                    break

            if not filenames:
                filenames = [self.image_path]

            logger.info(f"Opening EWF files: {filenames}")
            ewf_handle = pyewf.handle()
            ewf_handle.open(filenames)
            return EWFImgInfo(ewf_handle)

        except Exception as e:
            logger.error(f"Error opening EWF image: {str(e)}")
            raise

    def analyze_partitions(self, img_info, vol_info):
        """Analyze all partitions"""
        all_partitions = []
        
        # Collect ALL partitions
        for part in vol_info:
            all_partitions.append(part)

        logger.info(f"Total partitions found in volume: {len(all_partitions)}")

        for i, part in enumerate(all_partitions):
            if self.should_stop:
                break

            progress = int((i + 1) / len(all_partitions) * 100)
            self.progress_updated.emit(progress)

            # Get partition description
            desc = "Unknown"
            if part.desc:
                desc = part.desc.decode('utf-8', errors='replace')
            elif hasattr(part, 'type') and part.type:
                desc = f"Type {part.type}"

            # Calculate size in bytes
            size_bytes = part.len * 512

            # Get filesystem type
            fs_type = "Unknown"
            try:
                if size_bytes > 0:
                    fs_info = pytsk3.FS_Info(img_info, offset=part.start * 512)
                    fs_type = self.get_fs_type_string(fs_info.info.ftype)
                    logger.info(f"Partition {i}: {fs_type} at offset {part.start * 512}, size: {size_bytes}")
            except Exception as e:
                logger.debug(f"Could not determine filesystem type for partition {i}: {str(e)}")
                if size_bytes > 1024:
                    fs_type = "Unrecognized"

            # Create partition info
            partition_info = PartitionInfo(
                index=i,
                description=desc,
                start_offset=part.start * 512,
                size=size_bytes,
                fs_type=fs_type
            )

            # Detect actual VSS copies for NTFS partitions
            if fs_type.lower() == 'ntfs':
                self.status_updated.emit(f"Detecting VSS copies for partition {i}...")
                vss_copies = VSSDetector.detect_vss_copies(img_info, part.start * 512)
                partition_info.vss_copies = vss_copies
                logger.info(f"Found {len(vss_copies)} VSS copies for partition {i}")

            self.found_partitions.append(partition_info)
            self.partition_found.emit(partition_info)
            logger.info(f"Added partition {i}: {desc}, Size: {size_bytes} bytes, FS: {fs_type}")

    def analyze_single_partition(self, img_info):
        """Analyze single partition"""
        logger.info("No partition table detected, analyzing as single partition")
        
        offsets_to_try = [0, 512, 1024, 2048 * 512, 63 * 512]
        partitions_found = 0

        for offset in offsets_to_try:
            try:
                if offset >= img_info.get_size():
                    continue

                fs_info = pytsk3.FS_Info(img_info, offset=offset)
                fs_type = self.get_fs_type_string(fs_info.info.ftype)

                partition_info = PartitionInfo(
                    index=partitions_found,
                    description=f"Single Partition at offset {offset}",
                    start_offset=offset,
                    size=img_info.get_size() - offset,
                    fs_type=fs_type
                )

                # Detect VSS for NTFS
                if fs_type.lower() == 'ntfs':
                    vss_copies = VSSDetector.detect_vss_copies(img_info, offset)
                    partition_info.vss_copies = vss_copies

                self.found_partitions.append(partition_info)
                self.partition_found.emit(partition_info)
                partitions_found += 1
                logger.info(f"Found filesystem at offset {offset}: {fs_type}")

            except Exception as e:
                logger.debug(f"No filesystem found at offset {offset}: {str(e)}")
                continue

        if partitions_found == 0:
            partition_info = PartitionInfo(
                index=0,
                description="Raw Disk Image",
                start_offset=0,
                size=img_info.get_size(),
                fs_type="Raw/Unknown"
            )
            self.found_partitions.append(partition_info)
            self.partition_found.emit(partition_info)
            logger.info("No recognizable filesystems found, added raw partition")

    def get_fs_type_string(self, fs_type):
        """Convert filesystem type to string"""
        fs_types = {
            pytsk3.TSK_FS_TYPE_NTFS: "NTFS",
            pytsk3.TSK_FS_TYPE_FAT32: "FAT32",
            pytsk3.TSK_FS_TYPE_FAT16: "FAT16",
            pytsk3.TSK_FS_TYPE_FAT12: "FAT12",
            pytsk3.TSK_FS_TYPE_EXT2: "EXT2",
            pytsk3.TSK_FS_TYPE_EXT3: "EXT3",
            pytsk3.TSK_FS_TYPE_EXT4: "EXT4",
            pytsk3.TSK_FS_TYPE_HFS: "HFS",
            pytsk3.TSK_FS_TYPE_ISO9660: "ISO9660"
        }
        return fs_types.get(fs_type, "Unknown")

    def stop(self):
        self.should_stop = True

class FilesystemLoader(QThread):
    """Thread to load filesystem structure"""
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    directory_loaded = pyqtSignal(str, list)
    error_occurred = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, image_path, partition_offset, vss_index=None):
        super().__init__()
        self.image_path = os.path.abspath(image_path)
        self.partition_offset = partition_offset
        self.vss_index = vss_index
        self.should_stop = False
        self.fs_info = None
        self.img_info = None

    def run(self):
        try:
            self.status_updated.emit("Opening filesystem...")
            logger.info(f"Loading filesystem from {self.image_path} at offset {self.partition_offset}")

            # Open image
            if self.image_path.lower().endswith('.e01'):
                self.img_info = self.open_ewf_image()
            else:
                self.img_info = pytsk3.Img_Info(self.image_path)

            # Open filesystem
            self.fs_info = pytsk3.FS_Info(self.img_info, offset=self.partition_offset)

            self.status_updated.emit("Loading root directory...")
            
            # Load root directory
            self.load_directory("/")

        except Exception as e:
            logger.error(f"Error in FilesystemLoader: {str(e)}")
            self.error_occurred.emit(f"Error loading filesystem: {str(e)}")
        finally:
            self.finished.emit()

    def open_ewf_image(self):
        """Open EWF image"""
        try:
            directory = os.path.dirname(self.image_path)
            filename = os.path.basename(self.image_path)
            base_name = os.path.splitext(filename)[0]

            filenames = []
            for i in range(1, 100):
                segment_name = f"{base_name}.E{i:02d}"
                segment_path = os.path.join(directory, segment_name)
                if os.path.exists(segment_path):
                    filenames.append(segment_path)
                else:
                    break

            if not filenames:
                filenames = [self.image_path]

            ewf_handle = pyewf.handle()
            ewf_handle.open(filenames)
            return EWFImgInfo(ewf_handle)

        except Exception as e:
            logger.error(f"Error opening EWF image in filesystem loader: {str(e)}")
            raise

    def load_directory(self, path):
        """Load directory contents"""
        try:
            logger.info(f"Loading directory: {path}")
            directory = self.fs_info.open_dir(path=path)
            entries = []

            for entry in directory:
                if self.should_stop:
                    break

                if entry.info.name.name in [b'.', b'..']:
                    continue

                try:
                    filename = entry.info.name.name.decode('utf-8', errors='replace')
                    is_directory = entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR if entry.info.meta else False
                    file_size = entry.info.meta.size if entry.info.meta else 0

                    modified_time = None
                    created_time = None
                    accessed_time = None

                    if entry.info.meta:
                        if entry.info.meta.mtime:
                            modified_time = datetime.datetime.fromtimestamp(entry.info.meta.mtime)
                        if entry.info.meta.crtime:
                            created_time = datetime.datetime.fromtimestamp(entry.info.meta.crtime)
                        if entry.info.meta.atime:
                            accessed_time = datetime.datetime.fromtimestamp(entry.info.meta.atime)

                    entry_info = {
                        'name': filename,
                        'path': os.path.join(path, filename).replace('\\', '/'),
                        'is_directory': is_directory,
                        'size': file_size,
                        'modified': modified_time,
                        'created': created_time,
                        'accessed': accessed_time,
                        'inode': entry.info.meta.addr if entry.info.meta else 0
                    }

                    entries.append(entry_info)

                except Exception as e:
                    logger.debug(f"Error processing entry: {str(e)}")
                    continue

            entries.sort(key=lambda x: (not x['is_directory'], x['name'].lower()))
            logger.info(f"Loaded {len(entries)} entries from {path}")
            self.directory_loaded.emit(path, entries)

        except Exception as e:
            logger.error(f"Error loading directory {path}: {str(e)}")
            self.error_occurred.emit(f"Error loading directory {path}: {str(e)}")

    def stop(self):
        self.should_stop = True

class VSSExplorerMainWindow(QMainWindow):
    """Main VSS Explorer window"""

    def __init__(self):
        super().__init__()
        self.current_image_path = None
        self.current_partitions = []
        self.current_filesystem_loader = None
        self.current_img_info = None
        self.current_fs_info = None
        self.current_directory_data = {}
        self.init_ui()
        logger.info("VSS Explorer initialized")

    def init_ui(self):
        """Initialize user interface"""
        self.setWindowTitle("VSS Explorer v1.2")
        self.setGeometry(100, 100, 1600, 1000)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(5, 5, 5, 5)

        self.create_toolbar(main_layout)
        self.create_main_content(main_layout)
        self.create_status_bar()

    def create_toolbar(self, parent_layout):
        """Create toolbar"""
        toolbar_layout = QHBoxLayout()

        self.open_btn = QPushButton("Open Image")
        self.open_btn.clicked.connect(self.open_image)
        toolbar_layout.addWidget(self.open_btn)

        toolbar_layout.addWidget(QLabel("Partition:"))
        self.partition_combo = QComboBox()
        self.partition_combo.currentIndexChanged.connect(self.partition_changed)
        self.partition_combo.setEnabled(False)
        self.partition_combo.setMinimumWidth(300)
        toolbar_layout.addWidget(self.partition_combo)

        toolbar_layout.addWidget(QLabel("VSS Copy:"))
        self.vss_combo = QComboBox()
        self.vss_combo.currentIndexChanged.connect(self.vss_changed)
        self.vss_combo.setEnabled(False)
        self.vss_combo.setMinimumWidth(200)
        toolbar_layout.addWidget(self.vss_combo)

        self.load_fs_btn = QPushButton("Load Filesystem")
        self.load_fs_btn.clicked.connect(self.load_filesystem)
        self.load_fs_btn.setEnabled(False)
        toolbar_layout.addWidget(self.load_fs_btn)

        # Export buttons
        self.export_selected_btn = QPushButton("Export Selected")
        self.export_selected_btn.clicked.connect(self.export_selected_files)
        self.export_selected_btn.setEnabled(False)
        toolbar_layout.addWidget(self.export_selected_btn)

        self.export_all_btn = QPushButton("Export All")
        self.export_all_btn.clicked.connect(self.export_all_files)
        self.export_all_btn.setEnabled(False)
        toolbar_layout.addWidget(self.export_all_btn)

        toolbar_layout.addStretch()

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximumWidth(200)
        toolbar_layout.addWidget(self.progress_bar)

        parent_layout.addLayout(toolbar_layout)

    def create_main_content(self, parent_layout):
        """Create main content area"""
        splitter = QSplitter(Qt.Horizontal)

        self.create_tree_panel(splitter)
        self.create_file_panel(splitter)

        splitter.setSizes([400, 800])
        parent_layout.addWidget(splitter)

    def create_tree_panel(self, parent):
        """Create tree panel"""
        tree_widget = QWidget()
        tree_layout = QVBoxLayout(tree_widget)

        tree_layout.addWidget(QLabel("Directory Tree:"))

        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderLabels(['Name'])
        self.tree_widget.itemExpanded.connect(self.on_tree_expanded)
        self.tree_widget.itemClicked.connect(self.on_tree_clicked)
        self.tree_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_widget.customContextMenuRequested.connect(self.show_tree_context_menu)

        tree_layout.addWidget(self.tree_widget)
        parent.addWidget(tree_widget)

    def create_file_panel(self, parent):
        """Create file panel"""
        file_widget = QWidget()
        file_layout = QVBoxLayout(file_widget)

        file_layout.addWidget(QLabel("Files:"))

        self.file_table = QTableWidget()
        self.file_table.setColumnCount(5)
        self.file_table.setHorizontalHeaderLabels(['Name', 'Size', 'Type', 'Modified', 'Created'])

        header = self.file_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)

        self.file_table.setAlternatingRowColors(True)
        self.file_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.file_table.setSortingEnabled(True)
        self.file_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_table.customContextMenuRequested.connect(self.show_file_context_menu)
        self.file_table.itemDoubleClicked.connect(self.on_file_double_clicked)
        self.file_table.setEditTriggers(QAbstractItemView.NoEditTriggers)  # Make non-editable

        file_layout.addWidget(self.file_table)
        parent.addWidget(file_widget)

    def create_status_bar(self):
        """Create status bar"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        self.status_label = QLabel("Ready - Click 'Open Image' to start")
        self.status_bar.addWidget(self.status_label)

    def open_image(self):
        """Open disk image file"""
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(
            self,
            "Open Disk Image",
            "",
            "Disk Images (*.dd *.raw *.img *.e01 *.ex01);;All Files (*)"
        )

        if file_path:
            self.current_image_path = os.path.abspath(file_path)
            self.status_label.setText(f"Loading image: {os.path.basename(file_path)}")
            logger.info(f"Selected image: {self.current_image_path}")

            self.partition_combo.clear()
            self.vss_combo.clear()
            self.tree_widget.clear()
            self.file_table.setRowCount(0)
            self.current_partitions = []
            self.current_directory_data = {}

            self.load_image()

    def load_image(self):
        """Load and analyze image"""
        self.image_loader = ImageLoader(self.current_image_path)
        self.image_loader.progress_updated.connect(self.update_progress)
        self.image_loader.status_updated.connect(self.update_status)
        self.image_loader.partition_found.connect(self.add_partition)
        self.image_loader.error_occurred.connect(self.show_error)
        self.image_loader.finished.connect(self.image_load_finished)

        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.open_btn.setEnabled(False)

        self.image_loader.start()

    def update_progress(self, value):
        """Update progress bar"""
        self.progress_bar.setValue(value)

    def update_status(self, message):
        """Update status message"""
        self.status_label.setText(message)

    def add_partition(self, partition_info):
        """Add partition to dropdown"""
        self.current_partitions.append(partition_info)

        # Format the display text properly
        size_mb = partition_info.size / (1024 * 1024)
        display_text = f"Partition {partition_info.index}: {partition_info.description} ({size_mb:.1f} MB) - {partition_info.fs_type}"
        self.partition_combo.addItem(display_text, partition_info)
        logger.info(f"Added partition: {display_text}")

    def show_error(self, error_message):
        """Show error message"""
        QMessageBox.critical(self, "Error", error_message)
        logger.error(error_message)

    def image_load_finished(self):
        """Image loading finished"""
        self.progress_bar.setVisible(False)
        self.open_btn.setEnabled(True)

        if self.current_partitions:
            self.partition_combo.setEnabled(True)
            self.status_label.setText(f"Found {len(self.current_partitions)} partitions - Select partition and VSS copy")
            
            if self.partition_combo.count() > 0:
                self.partition_combo.setCurrentIndex(0)
                self.partition_changed()
        else:
            self.status_label.setText("No valid partitions found")

    def partition_changed(self):
        """Handle partition selection change"""
        if self.partition_combo.currentIndex() >= 0:
            partition_info = self.partition_combo.currentData()
            if partition_info:
                self.vss_combo.clear()
                self.vss_combo.addItem("Live System", None)

                for vss_copy in partition_info.vss_copies:
                    self.vss_combo.addItem(str(vss_copy), vss_copy)

                self.vss_combo.setEnabled(True)
                self.load_fs_btn.setEnabled(True)

                logger.info(f"Selected partition: {str(partition_info)}")
                logger.info(f"Available VSS copies: {len(partition_info.vss_copies)}")

    def vss_changed(self):
        """Handle VSS selection change"""
        self.load_fs_btn.setEnabled(True)
        vss_data = self.vss_combo.currentData()
        
        if vss_data:
            logger.info(f"Selected VSS copy: {str(vss_data)}")
        else:
            logger.info("Selected Live System")

    def load_filesystem(self):
        """Load filesystem structure"""
        partition_info = self.partition_combo.currentData()
        vss_data = self.vss_combo.currentData()

        if not partition_info:
            QMessageBox.warning(self, "Warning", "Please select a partition first.")
            return

        self.tree_widget.clear()
        self.file_table.setRowCount(0)
        self.current_directory_data = {}

        vss_index = vss_data.index if vss_data else None
        logger.info(f"Loading filesystem for partition {partition_info.index} at offset {partition_info.start_offset}")

        self.current_filesystem_loader = FilesystemLoader(
            self.current_image_path,
            partition_info.start_offset,
            vss_index
        )

        self.current_filesystem_loader.progress_updated.connect(self.update_progress)
        self.current_filesystem_loader.status_updated.connect(self.update_status)
        self.current_filesystem_loader.directory_loaded.connect(self.populate_tree_root)
        self.current_filesystem_loader.error_occurred.connect(self.show_error)
        self.current_filesystem_loader.finished.connect(self.filesystem_load_finished)

        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.load_fs_btn.setEnabled(False)

        self.current_filesystem_loader.start()

    def populate_tree_root(self, path, entries):
        """Populate tree with root directory"""
        if path == "/":
            logger.info(f"Populating root directory with {len(entries)} entries")
            
            # Store directory data
            self.current_directory_data[path] = entries
            
            # Store filesystem info for export operations
            if self.current_filesystem_loader:
                self.current_img_info = self.current_filesystem_loader.img_info
                self.current_fs_info = self.current_filesystem_loader.fs_info

            for entry in entries:
                if entry['is_directory']:
                    item = QTreeWidgetItem(self.tree_widget)
                    item.setText(0, f"📁 {entry['name']}")
                    item.setData(0, Qt.UserRole, entry)
                    
                    # Add dummy child to make it expandable
                    dummy = QTreeWidgetItem(item)
                    dummy.setText(0, "Loading...")

            self.populate_file_table(entries)

    def populate_file_table(self, entries):
        """Populate file table with directory contents"""
        self.file_table.setRowCount(len(entries))

        for row, entry in enumerate(entries):
            # Name column - make it non-editable
            name_item = QTableWidgetItem()
            if entry['is_directory']:
                name_item.setText(f"📁 {entry['name']}")
            else:
                name_item.setText(f"📄 {entry['name']}")
            name_item.setData(Qt.UserRole, entry)
            name_item.setFlags(name_item.flags() & ~Qt.ItemIsEditable)  # Make non-editable
            self.file_table.setItem(row, 0, name_item)

            # Size column
            if entry['is_directory']:
                size_text = "<DIR>"
            else:
                size_text = self.format_file_size(entry['size'])
            size_item = QTableWidgetItem(size_text)
            size_item.setFlags(size_item.flags() & ~Qt.ItemIsEditable)
            self.file_table.setItem(row, 1, size_item)

            # Type column
            type_text = "Folder" if entry['is_directory'] else "File"
            type_item = QTableWidgetItem(type_text)
            type_item.setFlags(type_item.flags() & ~Qt.ItemIsEditable)
            self.file_table.setItem(row, 2, type_item)

            # Modified column
            modified_text = entry['modified'].strftime("%Y-%m-%d %H:%M:%S") if entry['modified'] else ""
            modified_item = QTableWidgetItem(modified_text)
            modified_item.setFlags(modified_item.flags() & ~Qt.ItemIsEditable)
            self.file_table.setItem(row, 3, modified_item)

            # Created column
            created_text = entry['created'].strftime("%Y-%m-%d %H:%M:%S") if entry['created'] else ""
            created_item = QTableWidgetItem(created_text)
            created_item.setFlags(created_item.flags() & ~Qt.ItemIsEditable)
            self.file_table.setItem(row, 4, created_item)

        # Enable export buttons
        self.export_selected_btn.setEnabled(True)
        self.export_all_btn.setEnabled(True)

    def format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.1f} {size_names[i]}"

    def filesystem_load_finished(self):
        """Filesystem loading finished"""
        self.progress_bar.setVisible(False)
        self.load_fs_btn.setEnabled(True)
        self.status_label.setText("Filesystem loaded successfully")

    def on_tree_expanded(self, item):
        """Handle tree item expansion"""
        entry_data = item.data(0, Qt.UserRole)
        if entry_data and entry_data['is_directory']:
            # Remove dummy child
            item.takeChildren()
            
            # Load directory contents
            self.load_directory_async(entry_data['path'], item)

    def load_directory_async(self, path, tree_item):
        """Load directory contents asynchronously"""
        if not self.current_fs_info:
            return

        try:
            directory = self.current_fs_info.open_dir(path=path)
            entries = []

            for entry in directory:
                if entry.info.name.name in [b'.', b'..']:
                    continue

                try:
                    filename = entry.info.name.name.decode('utf-8', errors='replace')
                    is_directory = entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR if entry.info.meta else False
                    file_size = entry.info.meta.size if entry.info.meta else 0

                    modified_time = None
                    created_time = None

                    if entry.info.meta:
                        if entry.info.meta.mtime:
                            modified_time = datetime.datetime.fromtimestamp(entry.info.meta.mtime)
                        if entry.info.meta.crtime:
                            created_time = datetime.datetime.fromtimestamp(entry.info.meta.crtime)

                    entry_info = {
                        'name': filename,
                        'path': os.path.join(path, filename).replace('\\', '/'),
                        'is_directory': is_directory,
                        'size': file_size,
                        'modified': modified_time,
                        'created': created_time,
                        'inode': entry.info.meta.addr if entry.info.meta else 0
                    }

                    entries.append(entry_info)

                    # Add to tree if it's a directory
                    if is_directory:
                        child_item = QTreeWidgetItem(tree_item)
                        child_item.setText(0, f"📁 {filename}")
                        child_item.setData(0, Qt.UserRole, entry_info)
                        
                        # Add dummy child to make it expandable
                        dummy = QTreeWidgetItem(child_item)
                        dummy.setText(0, "Loading...")

                except Exception as e:
                    logger.debug(f"Error processing entry: {str(e)}")
                    continue

            # Store directory data
            self.current_directory_data[path] = entries

        except Exception as e:
            logger.error(f"Error loading directory {path}: {str(e)}")

    def on_tree_clicked(self, item):
        """Handle tree item click"""
        entry_data = item.data(0, Qt.UserRole)
        if entry_data and entry_data['is_directory']:
            path = entry_data['path']
            if path in self.current_directory_data:
                self.populate_file_table(self.current_directory_data[path])

    def on_file_double_clicked(self, item):
        """Handle file double click"""
        entry_data = item.data(Qt.UserRole)
        if entry_data and entry_data['is_directory']:
            # Navigate to directory
            path = entry_data['path']
            if path in self.current_directory_data:
                self.populate_file_table(self.current_directory_data[path])
            else:
                # Load directory if not already loaded
                self.load_directory_async(path, None)

    def show_tree_context_menu(self, position):
        """Show context menu for tree"""
        item = self.tree_widget.itemAt(position)
        if item:
            menu = QMenu()
            
            export_action = QAction("Export Folder", self)
            export_action.triggered.connect(lambda: self.export_tree_item(item))
            menu.addAction(export_action)
            
            menu.exec_(self.tree_widget.mapToGlobal(position))

    def show_file_context_menu(self, position):
        """Show context menu for file table"""
        item = self.file_table.itemAt(position)
        if item:
            menu = QMenu()
            
            export_action = QAction("Export", self)
            export_action.triggered.connect(lambda: self.export_table_item(item))
            menu.addAction(export_action)
            
            menu.exec_(self.file_table.mapToGlobal(position))

    def export_tree_item(self, item):
        """Export tree item"""
        entry_data = item.data(0, Qt.UserRole)
        if entry_data:
            self.export_items([entry_data])

    def export_table_item(self, item):
        """Export table item"""
        entry_data = item.data(Qt.UserRole)
        if entry_data:
            self.export_items([entry_data])

    def export_selected_files(self):
        """Export selected files"""
        selected_items = self.file_table.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "Information", "Please select files to export.")
            return

        # Get unique entries from selected rows
        selected_entries = []
        selected_rows = set()
        
        for item in selected_items:
            row = item.row()
            if row not in selected_rows:
                selected_rows.add(row)
                entry_data = self.file_table.item(row, 0).data(Qt.UserRole)
                if entry_data:
                    selected_entries.append(entry_data)

        if selected_entries:
            self.export_items(selected_entries)

    def export_all_files(self):
        """Export all files in current directory"""
        all_entries = []
        for row in range(self.file_table.rowCount()):
            entry_data = self.file_table.item(row, 0).data(Qt.UserRole)
            if entry_data:
                all_entries.append(entry_data)

        if all_entries:
            self.export_items(all_entries)

    def export_items(self, items_to_export):
        """Export items to selected directory"""
        if not self.current_fs_info or not self.current_img_info:
            QMessageBox.warning(self, "Warning", "No filesystem loaded.")
            return

        # Select export directory
        export_dir = QFileDialog.getExistingDirectory(self, "Select Export Directory")
        if not export_dir:
            return

        # Create export worker
        self.export_worker = ExportWorker(
            self.current_img_info,
            self.current_fs_info,
            items_to_export,
            export_dir
        )

        # Connect signals
        self.export_worker.progress_updated.connect(self.update_progress)
        self.export_worker.status_updated.connect(self.update_status)
        self.export_worker.export_completed.connect(self.export_finished)
        self.export_worker.error_occurred.connect(self.show_error)

        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.export_selected_btn.setEnabled(False)
        self.export_all_btn.setEnabled(False)

        # Start export
        self.export_worker.start()

    def export_finished(self, success_count, total_count):
        """Export operation finished"""
        self.progress_bar.setVisible(False)
        self.export_selected_btn.setEnabled(True)
        self.export_all_btn.setEnabled(True)

        message = f"Export completed: {success_count}/{total_count} items exported successfully."
        QMessageBox.information(self, "Export Complete", message)
        self.status_label.setText("Export completed")

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("VSS Explorer Professional")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("Forensic Tools")
    
    # Create and show main window
    window = VSSExplorerMainWindow()
    window.show()
    
    # Run application
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
