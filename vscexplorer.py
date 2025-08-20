import sys
import os
import logging
import datetime
import struct
import shutil
import re
import hashlib
import csv
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytsk3
import pyewf

# Check for optional libraries
try:
    import pyvshadow
    PYVSHADOW_AVAILABLE = True
except ImportError:
    PYVSHADOW_AVAILABLE = False

try:
    import pybde
    BITLOCKER_AVAILABLE = True
except ImportError:
    BITLOCKER_AVAILABLE = False

try:
    import win32api
    import win32file
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem,
    QSplitter, QMenuBar, QMenu, QAction, QFileDialog, QMessageBox,
    QComboBox, QLabel, QPushButton, QProgressBar, QStatusBar,
    QHeaderView, QAbstractItemView, QFrame, QGroupBox, QTextEdit,
    QGridLayout, QSpacerItem, QSizePolicy, QLineEdit, QDialog,
    QDialogButtonBox, QToolBar, QListWidget, QListWidgetItem,
    QTabWidget, QCheckBox, QRadioButton, QButtonGroup, QScrollArea,
    QFormLayout, QStyleFactory
)

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QRect, QFileInfo, QMutex, QMutexLocker
from PyQt5.QtGui import QIcon, QFont, QPixmap, QStandardItemModel, QStandardItem, QColor, QPalette

# Configure enhanced logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('forensic_explorer.log', encoding='utf-8')
    ]
)

logger = logging.getLogger('VSCExplorer')

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

class BitLockerFileObject:
    """File-like object for BitLocker partition access"""
    def __init__(self, img_info, offset, size):
        self.img_info = img_info
        self.partition_offset = offset
        self.partition_size = size
        self.position = 0

    def read(self, size=-1):
        if size == -1:
            size = self.partition_size - self.position
        if self.position + size > self.partition_size:
            size = self.partition_size - self.position
        if size <= 0:
            return b''
        data = self.img_info.read(self.partition_offset + self.position, size)
        self.position += len(data)
        return data

    def seek(self, position, whence=0):
        if whence == 0:
            self.position = position
        elif whence == 1:
            self.position += position
        elif whence == 2:
            self.position = self.partition_size + position
        self.position = max(0, min(self.position, self.partition_size))
        return self.position

    def tell(self):
        return self.position

    def close(self):
        pass

class DecryptedVolumeAccess(pytsk3.Img_Info):
    """Custom Img_Info class to access decrypted BitLocker volume through pybde"""
    def __init__(self, bde_volume):
        self.bde_volume = bde_volume
        super(DecryptedVolumeAccess, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        pass

    def read(self, offset, size):
        self.bde_volume.seek_offset(offset, 0)
        return self.bde_volume.read_buffer(size)

    def get_size(self):
        return self.bde_volume.get_size()

class VShadowVolume(object):
    """Volume wrapper for VSS access."""
    def __init__(self, img_info, offset):
        self._img_info = img_info
        self._offset = offset
        self._current_offset = 0

    def seek(self, offset, whence=0):
        if whence == 0:
            self._current_offset = offset
        elif whence == 1:
            self._current_offset += offset
        elif whence == 2:
            size = self._img_info.get_size() - self._offset
            self._current_offset = size + offset
        return self._current_offset

    def tell(self):
        return self._current_offset

    def read(self, size):
        try:
            data = self._img_info.read(self._offset + self._current_offset, size)
            self._current_offset += len(data)
            return data
        except Exception as e:
            logger.debug(f"Error reading from image: {str(e)}")
            return b''

    def close(self):
        pass

class VShadowImgInfo(pytsk3.Img_Info):
    """Interface for pytsk3 to access VSS stores."""
    def __init__(self, store):
        self._store = store
        super(VShadowImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._store.close()

    def read(self, offset, size):
        self._store.seek(offset)
        return self._store.read(size)

    def get_size(self):
        return self._store.get_size()

class BitLockerInfo:
    """Class to store comprehensive BitLocker information"""
    def __init__(self):
        self.is_encrypted = False
        self.volume_id = ""
        self.encryption_method = ""
        self.encryption_method_name = ""
        self.volume_label = ""
        self.creation_time = ""
        self.description = ""
        self.key_protectors = []
        self.is_unlocked = False
        self.bde_volume = None
        self.volume_size = 0

class KeyProtectorInfo:
    """Class to store key protector information"""
    def __init__(self, index, protector_type, type_code, guid):
        self.index = index
        self.protector_type = protector_type
        self.type_code = type_code
        self.guid = guid

class PartitionInfo:
    """Class to store partition information"""
    def __init__(self, index, description, start_offset, size, fs_type="Unknown"):
        self.index = index
        self.description = description
        self.start_offset = start_offset
        self.size = size
        self.fs_type = fs_type
        self.vss_copies = []
        self.bitlocker_info = BitLockerInfo()
        self.has_real_vss = False

    def __str__(self):
        size_mb = self.size / (1024 * 1024)
        bitlocker_status = " [BitLocker]" if self.bitlocker_info.is_encrypted else ""
        return f"Partition {self.index}: {self.description} ({size_mb:.1f} MB) - {self.fs_type}{bitlocker_status}"

class VSSCopy:
    """Enhanced class to store comprehensive VSS copy information"""
    def __init__(self, index, creation_time_utc, size=0, store_id="", shadow_copy_id="", provider=""):
        self.index = index
        self.creation_time_utc = creation_time_utc
        self.size = size
        self.store_id = store_id
        self.shadow_copy_id = shadow_copy_id
        self.provider = provider

    def __str__(self):
        return f"Shadow Copy {self.index+1} - {self.creation_time_utc}"

class ExportOptionsDialog(QDialog):
    """Improved dialog for export options with better visibility"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.generate_csv = False
        self.include_hashes = False
        self.hash_types = []
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Export Configuration")
        self.resize(500, 500)
        self.setModal(True)

        # Set window icon if available
        if os.path.exists("logo.png"):
            self.setWindowIcon(QIcon("logo.png"))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        # Title
        title = QLabel("Export Configuration")
        title.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #2196F3;
                padding: 12px;
            }
        """)
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # CSV Report option
        csv_group = QGroupBox("Export Summary Report")
        csv_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 8px;
                margin-top: 16px;
                padding-top: 16px;
                background-color: white;
                font-size: 14px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 16px;
                padding: 0 10px 0 10px;
                color: #333333;
            }
        """)
        csv_layout = QVBoxLayout()
        csv_layout.setSpacing(12)

        self.csv_checkbox = QCheckBox("Generate CSV export summary report")
        self.csv_checkbox.setChecked(True)
        self.csv_checkbox.setStyleSheet("""
            QCheckBox {
                font-size: 14px;
                font-weight: normal;
                padding: 8px;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 20px;
                height: 20px;
            }
        """)
        self.csv_checkbox.toggled.connect(self.on_csv_toggled)
        csv_layout.addWidget(self.csv_checkbox)

        csv_info = QLabel("Includes file metadata, timestamps, and export status")
        csv_info.setStyleSheet("""
            color: #666;
            font-size: 12px;
            margin-left: 30px;
            padding: 4px;
        """)
        csv_layout.addWidget(csv_info)

        csv_group.setLayout(csv_layout)
        layout.addWidget(csv_group)

        # Hash options
        self.hash_group = QGroupBox("File Hash Calculation")
        self.hash_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 8px;
                margin-top: 16px;
                padding-top: 16px;
                background-color: white;
                font-size: 14px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 16px;
                padding: 0 10px 0 10px;
                color: #333333;
            }
        """)
        hash_layout = QVBoxLayout()
        hash_layout.setSpacing(12)

        self.hash_checkbox = QCheckBox("Include file hashes in report")
        self.hash_checkbox.setStyleSheet("""
            QCheckBox {
                font-size: 14px;
                font-weight: normal;
                padding: 8px;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 20px;
                height: 20px;
            }
        """)
        self.hash_checkbox.toggled.connect(self.on_hash_toggled)
        hash_layout.addWidget(self.hash_checkbox)

        # Hash type selection
        self.hash_types_widget = QWidget()
        hash_types_layout = QVBoxLayout(self.hash_types_widget)
        hash_types_layout.setContentsMargins(30, 12, 0, 0)
        hash_types_layout.setSpacing(8)

        hash_label = QLabel("Select hash algorithms:")
        hash_label.setStyleSheet("font-weight: bold; margin-bottom: 8px; font-size: 13px;")
        hash_types_layout.addWidget(hash_label)

        self.md5_checkbox = QCheckBox("MD5")
        self.sha1_checkbox = QCheckBox("SHA-1")
        self.sha256_checkbox = QCheckBox("SHA-256")
        self.sha256_checkbox.setChecked(True)  # Default

        for checkbox in [self.md5_checkbox, self.sha1_checkbox, self.sha256_checkbox]:
            checkbox.setStyleSheet("""
                QCheckBox {
                    font-size: 13px;
                    padding: 4px;
                    spacing: 8px;
                }
                QCheckBox::indicator {
                    width: 16px;
                    height: 16px;
                }
            """)

        hash_types_layout.addWidget(self.md5_checkbox)
        hash_types_layout.addWidget(self.sha1_checkbox)
        hash_types_layout.addWidget(self.sha256_checkbox)

        hash_note = QLabel("⚠️ Note: Hash calculation may significantly increase export time")
        hash_note.setStyleSheet("""
            color: #f44336;
            font-size: 11px;
            font-style: italic;
            padding: 8px;
        """)
        hash_types_layout.addWidget(hash_note)

        self.hash_types_widget.setEnabled(False)
        hash_layout.addWidget(self.hash_types_widget)

        self.hash_group.setLayout(hash_layout)
        layout.addWidget(self.hash_group)

        # pywin32 warning if not available
        if not PYWIN32_AVAILABLE:
            warning_label = QLabel("⚠️ pywin32 not available - some timestamp preservation features may be limited")
            warning_label.setStyleSheet("""
                QLabel {
                    color: #ff9800;
                    font-size: 12px;
                    font-style: italic;
                    padding: 12px;
                    background-color: #fff3cd;
                    border: 1px solid #ffeaa7;
                    border-radius: 4px;
                }
            """)
            layout.addWidget(warning_label)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        ok_btn = QPushButton("Start Export")
        ok_btn.setFixedSize(140, 40)
        ok_btn.clicked.connect(self.accept)
        ok_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setFixedSize(120, 40)
        cancel_btn.clicked.connect(self.reject)
        cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)

        button_layout.addWidget(ok_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)

        # Initialize state
        self.on_csv_toggled(True)

    def on_csv_toggled(self, checked):
        self.hash_group.setEnabled(checked)
        if not checked:
            self.hash_checkbox.setChecked(False)

    def on_hash_toggled(self, checked):
        self.hash_types_widget.setEnabled(checked)

    def accept(self):
        self.generate_csv = self.csv_checkbox.isChecked()
        self.include_hashes = self.hash_checkbox.isChecked()

        if self.include_hashes:
            self.hash_types = []
            if self.md5_checkbox.isChecked():
                self.hash_types.append('md5')
            if self.sha1_checkbox.isChecked():
                self.hash_types.append('sha1')
            if self.sha256_checkbox.isChecked():
                self.hash_types.append('sha256')

            if not self.hash_types:
                QMessageBox.warning(self, "Warning", "Please select at least one hash algorithm.")
                return

        super().accept()

class BitLockerCredentialsDialog(QDialog):
    """Fixed BitLocker credentials dialog with proper radio button logic"""
    def __init__(self, bitlocker_info, parent=None):
        super().__init__(parent)
        self.bitlocker_info = bitlocker_info
        self.password = ""
        self.recovery_key = ""
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("BitLocker Volume Unlock")
        self.resize(600, 650)
        self.setModal(True)

        # Set window icon if available
        if os.path.exists("logo.png"):
            self.setWindowIcon(QIcon("logo.png"))

        # Remove help button
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self.setStyleSheet("""
            QDialog {
                background-color: #f5f5f5;
                font-size: 14px;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 8px;
                margin-top: 16px;
                padding-top: 16px;
                background-color: white;
                font-size: 14px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 16px;
                padding: 0 10px 0 10px;
                color: #333333;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
                min-width: 90px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3e8e41;
            }
            QLineEdit {
                padding: 10px;
                border: 2px solid #ddd;
                border-radius: 6px;
                font-size: 14px;
                background-color: white;
                min-height: 25px;
            }
            QLineEdit:focus {
                border-color: #4CAF50;
            }
            QLabel {
                font-size: 14px;
            }
            QRadioButton {
                font-size: 14px;
                spacing: 8px;
                padding: 6px;
            }
            QRadioButton::indicator {
                width: 18px;
                height: 18px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        # Title with lock icon
        title_layout = QHBoxLayout()
        title = QLabel("🔒 BitLocker Encrypted Volume")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #d32f2f; margin: 10px; padding: 10px;")
        title_layout.addStretch()
        title_layout.addWidget(title)
        title_layout.addStretch()
        layout.addLayout(title_layout)

        # Volume Info with better visibility
        info_group = QGroupBox("Volume Information")
        info_layout = QFormLayout()
        info_layout.setSpacing(12)

        # Create labels with better formatting
        volume_id_label = QLabel(self.bitlocker_info.volume_id or "Unknown")
        volume_id_label.setStyleSheet("""
            font-family: 'Courier New';
            background-color: #f0f0f0;
            padding: 8px;
            border-radius: 4px;
            font-size: 13px;
        """)

        size_text = f"{self.bitlocker_info.volume_size // (1024*1024):,} MB" if self.bitlocker_info.volume_size > 0 else "Unknown"
        size_label = QLabel(size_text)
        size_label.setStyleSheet("font-weight: bold; color: #2196F3; font-size: 14px;")

        encryption_label = QLabel(self.bitlocker_info.encryption_method_name or "Unknown")
        encryption_label.setStyleSheet("font-weight: bold; color: #ff9800; font-size: 14px;")

        creation_label = QLabel(self.bitlocker_info.creation_time or "Unknown")
        creation_label.setStyleSheet("font-family: 'Courier New'; font-size: 13px;")

        info_layout.addRow("Volume ID:", volume_id_label)
        info_layout.addRow("Size:", size_label)
        info_layout.addRow("Encryption:", encryption_label)
        info_layout.addRow("Created:", creation_label)
        info_layout.addRow("Description:", QLabel(self.bitlocker_info.description or "Unknown"))

        info_group.setLayout(info_layout)
        layout.addWidget(info_group)

        # Key Protectors with proper visibility
        if self.bitlocker_info.key_protectors:
            key_group = QGroupBox("Available Key Protectors")
            key_layout = QVBoxLayout()
            key_layout.setSpacing(8)

            for kp in self.bitlocker_info.key_protectors:
                kp_widget = QWidget()
                kp_widget_layout = QVBoxLayout(kp_widget)
                kp_widget_layout.setContentsMargins(0, 0, 0, 0)
                kp_widget_layout.setSpacing(6)

                kp_text = f"🔑 {kp.protector_type}"
                kp_label = QLabel(kp_text)
                kp_label.setStyleSheet("""
                    border: 1px solid #4CAF50;
                    padding: 10px;
                    margin: 3px;
                    border-radius: 6px;
                    background-color: #f0f8ff;
                    font-weight: bold;
                    font-size: 14px;
                """)

                # Add GUID if available
                if kp.guid and kp.guid != "N/A":
                    guid_label = QLabel(f"ID: {kp.guid}")
                    guid_label.setStyleSheet("""
                        font-size: 12px;
                        color: #666;
                        font-family: 'Courier New';
                        margin-left: 16px;
                        padding: 4px;
                    """)
                    kp_widget_layout.addWidget(guid_label)

                kp_widget_layout.addWidget(kp_label)
                key_layout.addWidget(kp_widget)

            key_group.setLayout(key_layout)
            layout.addWidget(key_group)

        # Determine available key protectors to show only relevant options
        has_password = any("Password" in kp.protector_type for kp in self.bitlocker_info.key_protectors)
        has_recovery = any("Recovery" in kp.protector_type for kp in self.bitlocker_info.key_protectors)

        # Credentials - Fixed logic to show proper UI elements
        cred_group = QGroupBox("Unlock Credentials")
        cred_layout = QVBoxLayout()
        cred_layout.setSpacing(16)

        # Initialize radio buttons and input fields
        self.password_radio = None
        self.recovery_radio = None
        self.password_edit = None
        self.recovery_edit = None

        # Create radio buttons only if both types are available
        if has_password and has_recovery:
            radio_layout = QHBoxLayout()
            self.password_radio = QRadioButton("🔑 Password")
            self.recovery_radio = QRadioButton("🔐 Recovery Key")
            self.password_radio.setChecked(True)
            self.password_radio.setStyleSheet("font-weight: bold; padding: 8px; font-size: 14px;")
            self.recovery_radio.setStyleSheet("font-weight: bold; padding: 8px; font-size: 14px;")
            radio_layout.addWidget(self.password_radio)
            radio_layout.addWidget(self.recovery_radio)
            cred_layout.addLayout(radio_layout)
            
            # Connect toggle signal
            self.password_radio.toggled.connect(self.toggle_inputs)
        elif has_password:
            # Only password available
            label = QLabel("🔑 Password Authentication")
            label.setStyleSheet("font-weight: bold; padding: 8px; font-size: 14px;")
            cred_layout.addWidget(label)
        elif has_recovery:
            # Only recovery key available
            label = QLabel("🔐 Recovery Key Authentication")
            label.setStyleSheet("font-weight: bold; padding: 8px; font-size: 14px;")
            cred_layout.addWidget(label)
        else:
            # Unknown - show both options
            radio_layout = QHBoxLayout()
            self.password_radio = QRadioButton("🔑 Password")
            self.recovery_radio = QRadioButton("🔐 Recovery Key")
            self.password_radio.setChecked(True)
            self.password_radio.setStyleSheet("font-weight: bold; padding: 8px; font-size: 14px;")
            self.recovery_radio.setStyleSheet("font-weight: bold; padding: 8px; font-size: 14px;")
            radio_layout.addWidget(self.password_radio)
            radio_layout.addWidget(self.recovery_radio)
            cred_layout.addLayout(radio_layout)
            
            # Connect toggle signal
            self.password_radio.toggled.connect(self.toggle_inputs)

        # Create input fields based on what's available
        if has_password or not (has_password or has_recovery):
            self.password_edit = QLineEdit()
            self.password_edit.setEchoMode(QLineEdit.Password)
            self.password_edit.setPlaceholderText("Enter BitLocker password")
            cred_layout.addWidget(self.password_edit)

        if has_recovery or not (has_password or has_recovery):
            self.recovery_edit = QLineEdit()
            self.recovery_edit.setPlaceholderText("Enter 48-digit recovery key (######-######-######-######-######-######-######-######)")
            cred_layout.addWidget(self.recovery_edit)

        # Set initial visibility based on available options
        if has_password and has_recovery:
            # Both available - show password first
            if self.recovery_edit:
                self.recovery_edit.hide()
        elif has_password and not has_recovery:
            # Only password - hide recovery field
            if self.recovery_edit:
                self.recovery_edit.hide()
        elif has_recovery and not has_password:
            # Only recovery - hide password field
            if self.password_edit:
                self.password_edit.hide()
        # If neither detected, show both (fallback)

        cred_group.setLayout(cred_layout)
        layout.addWidget(cred_group)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        unlock_btn = QPushButton("🔓 Unlock Volume")
        unlock_btn.setFixedSize(160, 45)
        unlock_btn.clicked.connect(self.accept)
        unlock_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                font-size: 15px;
                padding: 12px 24px;
                min-width: 140px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)

        cancel_btn = QPushButton("❌ Cancel")
        cancel_btn.setFixedSize(140, 45)
        cancel_btn.clicked.connect(self.reject)
        cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                font-size: 15px;
                padding: 12px 24px;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)

        button_layout.addWidget(unlock_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)

    def toggle_inputs(self):
        """Toggle between password and recovery key inputs"""
        if self.password_radio and self.recovery_radio and self.password_edit and self.recovery_edit:
            if self.password_radio.isChecked():
                self.password_edit.show()
                self.recovery_edit.hide()
                self.password_edit.setFocus()
            else:
                self.password_edit.hide()
                self.recovery_edit.show()
                self.recovery_edit.setFocus()

    def accept(self):
        """Handle unlock button click"""
        if self.password_radio and self.password_radio.isChecked() and self.password_edit:
            self.password = self.password_edit.text().strip()
            if not self.password:
                QMessageBox.warning(self, "Warning", "Please enter a password.")
                return
        elif self.recovery_radio and self.recovery_radio.isChecked() and self.recovery_edit:
            self.recovery_key = self.recovery_edit.text().strip()
            if not self.recovery_key:
                QMessageBox.warning(self, "Warning", "Please enter a recovery key.")
                return
        elif self.password_edit and self.password_edit.isVisible():
            # Single password field visible
            self.password = self.password_edit.text().strip()
            if not self.password:
                QMessageBox.warning(self, "Warning", "Please enter a password.")
                return
        elif self.recovery_edit and self.recovery_edit.isVisible():
            # Single recovery field visible
            self.recovery_key = self.recovery_edit.text().strip()
            if not self.recovery_key:
                QMessageBox.warning(self, "Warning", "Please enter a recovery key.")
                return

        super().accept()

class BitLockerAnalyzer:
    """BitLocker analysis functionality with proper recovery key handling"""
    @staticmethod
    def detect_bitlocker(img_info, partition_offset):
        """Detect if partition is BitLocker encrypted"""
        try:
            boot_sector = img_info.read(partition_offset, 512)
            return b'-FVE-FS-' in boot_sector
        except Exception:
            return False

    @staticmethod
    def format_recovery_key(recovery_key):
        """Format recovery key properly for pybde"""
        # Remove all non-digit characters
        clean_key = re.sub(r'[^0-9]', '', recovery_key)
        
        # Ensure it's exactly 48 digits
        if len(clean_key) != 48:
            raise ValueError(f"Recovery key must be exactly 48 digits, got {len(clean_key)}")
        
        # Format with dashes
        formatted = '-'.join([clean_key[i:i+6] for i in range(0, 48, 6)])
        return formatted

    @staticmethod
    def analyze_bitlocker_volume(img_info, partition_offset, partition_size):
        """Analyze BitLocker volume and extract comprehensive information"""
        bitlocker_info = BitLockerInfo()
        
        if not BITLOCKER_AVAILABLE:
            logger.warning("BitLocker analysis not available - pybde library not installed")
            return bitlocker_info

        try:
            # Create BDE volume object
            bde_volume = pybde.volume()
            
            # Create file-like object for the partition
            partition_file = BitLockerFileObject(img_info, partition_offset, partition_size)
            
            # Open the BitLocker volume
            bde_volume.open_file_object(partition_file)
            
            bitlocker_info.is_encrypted = True
            bitlocker_info.volume_size = partition_size
            
            # Get basic volume information
            try:
                bitlocker_info.volume_id = bde_volume.get_volume_identifier()
            except:
                bitlocker_info.volume_id = "Unknown"
            
            try:
                encryption_method = bde_volume.get_encryption_method()
                encryption_methods = {
                    32768: "AES 128-bit with Diffuser",
                    32769: "AES 256-bit with Diffuser",
                    32770: "AES 128-bit",
                    32771: "AES 256-bit",
                    32772: "AES 256-bit XTS"
                }
                bitlocker_info.encryption_method = encryption_method
                bitlocker_info.encryption_method_name = encryption_methods.get(
                    encryption_method, f"Unknown (Code: {encryption_method})"
                )
            except:
                bitlocker_info.encryption_method = 0
                bitlocker_info.encryption_method_name = "Unknown"
            
            try:
                bitlocker_info.description = bde_volume.get_description()
            except:
                bitlocker_info.description = "BitLocker Encrypted Volume"
            
            try:
                creation_time = bde_volume.get_creation_time()
                if creation_time:
                    if hasattr(creation_time, 'strftime'):
                        bitlocker_info.creation_time = creation_time.strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        bitlocker_info.creation_time = str(creation_time)
                else:
                    bitlocker_info.creation_time = "Unknown"
            except:
                bitlocker_info.creation_time = "Unknown"
            
            # Get key protectors with better error handling
            try:
                num_protectors = bde_volume.get_number_of_key_protectors()
                for i in range(num_protectors):
                    try:
                        kp = bde_volume.get_key_protector(i)
                        
                        # Get protector type
                        type_code = None
                        try:
                            if hasattr(kp, 'get_type'):
                                type_code = kp.get_type()
                        except:
                            pass
                        
                        # Map type code to description
                        type_description = BitLockerAnalyzer.get_key_protector_type_name(type_code)
                        
                        # Get GUID with better handling
                        guid = "N/A"
                        try:
                            if hasattr(kp, 'get_identifier'):
                                guid_raw = kp.get_identifier()
                                if guid_raw:
                                    if isinstance(guid_raw, bytes):
                                        guid = guid_raw.decode('utf-8', errors='replace')
                                    else:
                                        guid = str(guid_raw)
                        except:
                            pass
                        
                        key_protector = KeyProtectorInfo(i, type_description, type_code, guid)
                        bitlocker_info.key_protectors.append(key_protector)
                        
                    except Exception as e:
                        logger.debug(f"Error reading key protector {i}: {e}")
            except Exception as e:
                logger.debug(f"Error reading key protectors: {e}")
            
            bitlocker_info.bde_volume = bde_volume
            
        except Exception as e:
            logger.error(f"Error analyzing BitLocker volume: {e}")
        
        return bitlocker_info

    @staticmethod
    def get_key_protector_type_name(type_code):
        """Map BitLocker key protector type codes to human-readable names"""
        type_map = {
            8192: "TPM/Hardware-based",
            2048: "Recovery Password", 
            512: "Password",
            256: "Smart Card"
        }
        
        if type_code in type_map:
            return type_map[type_code]
        else:
            return f"Unknown Type (Code: {type_code})" if type_code else "Unknown"

    @staticmethod
    def unlock_bitlocker_volume(bitlocker_info, password=None, recovery_key=None):
        """Unlock BitLocker volume with proper recovery key handling"""
        if not bitlocker_info.bde_volume:
            return False

        try:
            unlocked = False
            
            # Try password first
            if password:
                try:
                    logger.info("Trying password unlock...")
                    bitlocker_info.bde_volume.set_password(password.encode('utf-8'))
                    bitlocker_info.bde_volume.unlock()
                    if not bitlocker_info.bde_volume.is_locked():
                        logger.info("Password unlock successful!")
                        unlocked = True
                        bitlocker_info.is_unlocked = True
                        return True
                except Exception as e:
                    logger.debug(f"Password unlock failed: {e}")
            
            # Try recovery key with multiple methods
            if not unlocked and recovery_key:
                try:
                    logger.info("Trying recovery key unlock...")
                    
                    # Format the recovery key properly
                    formatted_key = BitLockerAnalyzer.format_recovery_key(recovery_key)
                    logger.info(f"Formatted recovery key: {formatted_key}")
                    
                    # Try different methods to set the recovery key
                    methods_to_try = [
                        ('set_recovery_password', formatted_key),
                        ('set_recovery_password', recovery_key),
                        ('set_recovery_password', re.sub(r'[^0-9]', '', recovery_key))
                    ]
                    
                    for method_name, key_format in methods_to_try:
                        try:
                            logger.info(f"Trying method: {method_name} with format: {key_format[:20]}...")
                            if hasattr(bitlocker_info.bde_volume, method_name):
                                getattr(bitlocker_info.bde_volume, method_name)(key_format.encode('utf-8'))
                                bitlocker_info.bde_volume.unlock()
                                if not bitlocker_info.bde_volume.is_locked():
                                    logger.info(f"Recovery key unlock successful with method: {method_name}!")
                                    unlocked = True
                                    bitlocker_info.is_unlocked = True
                                    return True
                        except Exception as method_error:
                            logger.debug(f"Method {method_name} failed: {method_error}")
                            continue
                    
                    if not unlocked:
                        logger.warning("All recovery key methods failed")
                        
                except Exception as e:
                    logger.error(f"Recovery key error: {e}")
            
            return False
            
        except Exception as e:
            logger.error(f"Error unlocking BitLocker volume: {e}")
            return False

class VSSDetector:
    """Enhanced VSS detector with proper pyvshadow implementation and BitLocker support"""
    @staticmethod
    def get_vss_creation_time(store, store_index):
        """Get VSS creation time with proper type handling."""
        try:
            creation_time = store.get_creation_time()
            
            # Handle different return types from pyvshadow
            if isinstance(creation_time, datetime.datetime):
                # If it's already a datetime object, use it directly
                return creation_time.strftime('%Y-%m-%d %H:%M:%S')
            elif isinstance(creation_time, (int, float)):
                # If it's a timestamp, convert it
                creation_dt = datetime.datetime.fromtimestamp(creation_time)
                return creation_dt.strftime('%Y-%m-%d %H:%M:%S')
            elif hasattr(creation_time, 'timestamp'):
                # If it has a timestamp method, use it
                timestamp = creation_time.timestamp()
                creation_dt = datetime.datetime.fromtimestamp(timestamp)
                return creation_dt.strftime('%Y-%m-%d %H:%M:%S')
            else:
                # Try to convert to string and parse
                time_str = str(creation_time)
                if time_str and time_str != "None":
                    try:
                        creation_dt = datetime.datetime.fromisoformat(time_str.replace('T', ' ').replace('Z', ''))
                        return creation_dt.strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        return "Unknown"
                else:
                    return "Unknown"
                    
        except Exception as e:
            logger.debug(f"Error getting creation time for VSS {store_index}: {str(e)}")
            return "Unknown"

    @staticmethod
    def detect_vss_copies(img_info_or_partition, partition_offset=None, is_bitlocker=False):
        """Detect VSS copies using pyvshadow with proper BitLocker support"""
        vss_copies = []
        
        if not PYVSHADOW_AVAILABLE:
            logger.warning("pyvshadow not available - VSS detection disabled")
            return vss_copies

        try:
            # Determine how to access the volume
            if is_bitlocker:
                # For BitLocker volumes, we expect a partition info object with unlocked bde_volume
                if hasattr(img_info_or_partition, 'bitlocker_info') and img_info_or_partition.bitlocker_info.is_unlocked:
                    logger.info("Detecting VSS on unlocked BitLocker volume")
                    # Create a wrapper for the decrypted BitLocker volume
                    volume_object = VShadowVolume(DecryptedVolumeAccess(img_info_or_partition.bitlocker_info.bde_volume), 0)
                else:
                    logger.error("BitLocker volume not unlocked properly")
                    return vss_copies
            else:
                # Regular volume - img_info_or_partition should be img_info
                logger.info(f"Detecting VSS on regular volume at offset {partition_offset}")
                volume_object = VShadowVolume(img_info_or_partition, partition_offset or 0)

            # Try to open VSS volume
            try:
                vshadow_volume = pyvshadow.volume()
                vshadow_volume.open_file_object(volume_object)
                logger.info("Successfully opened VShadow volume")
                
                # Get the number of stores
                number_of_stores = vshadow_volume.get_number_of_stores()
                logger.info(f"Found {number_of_stores} VSS stores")
                
                # Get information about each store
                for store_index in range(number_of_stores):
                    try:
                        store = vshadow_volume.get_store(store_index)
                        
                        # Get creation time with proper handling
                        creation_time_str = VSSDetector.get_vss_creation_time(store, store_index)
                        
                        # Get store identifier
                        try:
                            store_id = str(store.identifier)
                        except:
                            store_id = f"VSS_{store_index:02d}"
                        
                        # Get store size
                        try:
                            store_size = store.get_size()
                        except:
                            store_size = 0
                        
                        vss_copy = VSSCopy(
                            index=store_index,
                            creation_time_utc=creation_time_str,
                            size=store_size,
                            store_id=store_id,
                            shadow_copy_id=store_id,
                            provider="Microsoft Software Shadow Copy provider 1.0"
                        )
                        
                        vss_copies.append(vss_copy)
                        logger.info(f"Found VSS store: VSS {store_index} - Created: {creation_time_str} UTC")
                        
                    except Exception as e:
                        logger.error(f"Error processing VSS store {store_index}: {e}")
                        continue
                        
            except Exception as e:
                logger.debug(f"Error opening VShadow volume: {str(e)}")
                
        except Exception as e:
            logger.error(f"Error in VSS detection: {str(e)}")

        return vss_copies

class ForensicExportWorker(QThread):
    """Enhanced forensic worker thread with CSV report and hash generation"""
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    export_completed = pyqtSignal(int, int)
    error_occurred = pyqtSignal(str)

    def __init__(self, img_info, fs_info, items_to_export, export_path, options=None):
        super().__init__()
        self.img_info = img_info
        self.fs_info = fs_info
        self.items_to_export = items_to_export
        self.export_path = export_path
        self.should_stop = False
        self.options = options or {}
        self.export_records = []
        self.mutex = QMutex()

    def run(self):
        success_count = 0
        total_count = len(self.items_to_export)

        try:
            os.makedirs(self.export_path, exist_ok=True)

            for i, item_data in enumerate(self.items_to_export):
                with QMutexLocker(self.mutex):
                    if self.should_stop:
                        break

                progress = int((i / total_count) * 100)
                self.progress_updated.emit(progress)

                try:
                    if item_data['is_directory']:
                        self.status_updated.emit(f"Exporting folder: {item_data['name']}")
                        if self._export_directory_forensic(item_data):
                            success_count += 1
                    else:
                        self.status_updated.emit(f"Exporting file: {item_data['name']}")
                        if self._export_file_forensic(item_data):
                            success_count += 1
                            
                except Exception as e:
                    logger.error(f"Error exporting {item_data['name']}: {str(e)}")
                    self.error_occurred.emit(f"Error exporting {item_data['name']}: {str(e)}")
                    # Add failed export to records
                    if self.options.get('generate_csv', False):
                        self._add_export_record(item_data, False, str(e))

            # Generate CSV report if requested
            if self.options.get('generate_csv', False):
                self._generate_csv_report()

            self.export_completed.emit(success_count, total_count)

        except Exception as e:
            logger.error(f"Export operation failed: {str(e)}")
            self.error_occurred.emit(f"Export operation failed: {str(e)}")

    def _export_file_forensic(self, file_data):
        """Export a single file preserving MACB timestamps and calculating hashes"""
        try:
            file_path = file_data['path']
            file_name = file_data['name']
            
            # Sanitize filename for filesystem
            safe_filename = re.sub(r'[<>:"/\\|?*]', '_', file_name)
            
            file_obj = self.fs_info.open(path=file_path)
            export_file_path = os.path.join(self.export_path, safe_filename)
            
            # Initialize hash calculators if needed
            hash_calculators = {}
            if self.options.get('include_hashes', False):
                for hash_type in self.options.get('hash_types', []):
                    if hash_type == 'md5':
                        hash_calculators['md5'] = hashlib.md5()
                    elif hash_type == 'sha1':
                        hash_calculators['sha1'] = hashlib.sha1()
                    elif hash_type == 'sha256':
                        hash_calculators['sha256'] = hashlib.sha256()
            
            # Export file content with hash calculation
            with open(export_file_path, 'wb') as output_file:
                offset = 0
                file_size = file_data.get('size', 0)
                
                while offset < file_size:
                    with QMutexLocker(self.mutex):
                        if self.should_stop:
                            return False
                    
                    chunk_size = min(64 * 1024, file_size - offset)
                    try:
                        data = file_obj.read_random(offset, chunk_size)
                        if not data:
                            break
                    except:
                        # Handle read errors gracefully
                        logger.warning(f"Read error at offset {offset} for file {file_name}")
                        break
                    
                    output_file.write(data)
                    
                    # Update hash calculators
                    for hash_calc in hash_calculators.values():
                        hash_calc.update(data)
                    
                    offset += len(data)
            
            # Preserve MACB timestamps
            self._preserve_timestamps(export_file_path, file_data)
            
            # Calculate final hashes
            calculated_hashes = {}
            for hash_type, hash_calc in hash_calculators.items():
                calculated_hashes[hash_type] = hash_calc.hexdigest()
            
            # Add to export records
            if self.options.get('generate_csv', False):
                self._add_export_record(file_data, True, calculated_hashes=calculated_hashes)
            
            return True
            
        except Exception as e:
            logger.error(f"Error exporting file {file_data['name']}: {str(e)}")
            if self.options.get('generate_csv', False):
                self._add_export_record(file_data, False, str(e))
            return False

    def _export_directory_forensic(self, dir_data):
        """Export a directory preserving all metadata"""
        try:
            dir_name = dir_data['name']
            safe_dirname = re.sub(r'[<>:"/\\|?*]', '_', dir_name)
            export_dir_path = os.path.join(self.export_path, safe_dirname)
            
            os.makedirs(export_dir_path, exist_ok=True)
            
            # Preserve directory timestamps
            self._preserve_timestamps(export_dir_path, dir_data)
            
            # Add to export records
            if self.options.get('generate_csv', False):
                self._add_export_record(dir_data, True)
            
            return True
            
        except Exception as e:
            logger.error(f"Error exporting directory {dir_data['name']}: {e}")
            if self.options.get('generate_csv', False):
                self._add_export_record(dir_data, False, str(e))
            return False

    def _preserve_timestamps(self, file_path, file_data):
        """Preserve MACB timestamps forensically"""
        try:
            # Basic timestamp preservation that works without pywin32
            current_time = datetime.datetime.now().timestamp()
            
            # Set access and modification times
            atime = file_data.get('accessed').timestamp() if file_data.get('accessed') else current_time
            mtime = file_data.get('modified').timestamp() if file_data.get('modified') else current_time
            
            os.utime(file_path, (atime, mtime))
            
            # If pywin32 is available, try to set creation time as well
            if PYWIN32_AVAILABLE:
                try:
                    import win32file
                    import win32con
                    import pywintypes
                    
                    # Convert datetime to FILETIME
                    def datetime_to_filetime(dt):
                        if dt:
                            timestamp = dt.timestamp()
                            # Convert to Windows FILETIME (100-nanosecond intervals since 1601-01-01)
                            return int((timestamp + 11644473600) * 10000000)
                        return None
                    
                    handle = win32file.CreateFile(
                        file_path,
                        win32con.GENERIC_WRITE,
                        0,
                        None,
                        win32con.OPEN_EXISTING,
                        0,
                        None
                    )
                    
                    created_ft = datetime_to_filetime(file_data.get('created'))
                    modified_ft = datetime_to_filetime(file_data.get('modified'))
                    accessed_ft = datetime_to_filetime(file_data.get('accessed'))
                    
                    win32file.SetFileTime(handle, created_ft, accessed_ft, modified_ft)
                    handle.close()
                    
                except Exception as e:
                    logger.debug(f"Advanced timestamp preservation failed for {file_path}: {e}")
                    
        except Exception as e:
            logger.debug(f"Error preserving timestamps for {file_path}: {e}")

    def _add_export_record(self, file_data, success, error_msg=None, calculated_hashes=None):
        """Add export record for CSV report"""
        record = {
            'Name': file_data['name'],
            'Path': file_data['path'],
            'Type': 'Directory' if file_data['is_directory'] else 'File',
            'Size': file_data['size'] if not file_data['is_directory'] else 0,
            'Modified': file_data.get('modified', '').strftime('%Y-%m-%d %H:%M:%S') if file_data.get('modified') else '',
            'Created': file_data.get('created', '').strftime('%Y-%m-%d %H:%M:%S') if file_data.get('created') else '',
            'Accessed': file_data.get('accessed', '').strftime('%Y-%m-%d %H:%M:%S') if file_data.get('accessed') else '',
            'Export_Status': 'Success' if success else 'Failed',
            'Export_Time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'Error': error_msg if error_msg else ''
        }
        
        # Add hash values if calculated
        if calculated_hashes:
            for hash_type, hash_value in calculated_hashes.items():
                record[f'{hash_type.upper()}_Hash'] = hash_value
        elif self.options.get('include_hashes', False) and not file_data['is_directory']:
            # Add empty hash columns for consistency
            for hash_type in self.options.get('hash_types', []):
                record[f'{hash_type.upper()}_Hash'] = ''
        
        self.export_records.append(record)

    def _generate_csv_report(self):
        """Generate CSV export summary report"""
        try:
            csv_path = os.path.join(self.export_path, 'export_summary.csv')
            
            if not self.export_records:
                return
            
            # Get all unique field names
            fieldnames = set()
            for record in self.export_records:
                fieldnames.update(record.keys())
            fieldnames = sorted(list(fieldnames))
            
            with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.export_records)
            
            logger.info(f"CSV export report generated: {csv_path}")
            
        except Exception as e:
            logger.error(f"Error generating CSV report: {e}")

    def stop(self):
        with QMutexLocker(self.mutex):
            self.should_stop = True

class FileIconProvider:
    """Provide file icons based on extension"""
    @staticmethod
    def get_file_icon(filename, is_directory):
        """Get appropriate icon for file/directory"""
        if is_directory:
            return "📁"
        
        # Get file extension
        ext = os.path.splitext(filename.lower())[1]
        
        # Icon mapping
        icon_map = {
            # Documents
            '.txt': '📄', '.doc': '📝', '.docx': '📝', '.pdf': '📋',
            '.rtf': '📝', '.odt': '📝', '.pages': '📝',
            # Spreadsheets
            '.xls': '📊', '.xlsx': '📊', '.csv': '📊', '.ods': '📊',
            # Presentations
            '.ppt': '📊', '.pptx': '📊', '.odp': '📊', '.key': '📊',
            # Images
            '.jpg': '🖼️', '.jpeg': '🖼️', '.png': '🖼️', '.gif': '🖼️',
            '.bmp': '🖼️', '.tiff': '🖼️', '.tif': '🖼️', '.ico': '🖼️',
            '.svg': '🖼️', '.webp': '🖼️',
            # Videos
            '.mp4': '🎬', '.avi': '🎬', '.mov': '🎬', '.wmv': '🎬',
            '.flv': '🎬', '.mkv': '🎬', '.webm': '🎬', '.m4v': '🎬',
            # Audio
            '.mp3': '🎵', '.wav': '🎵', '.flac': '🎵', '.aac': '🎵',
            '.ogg': '🎵', '.wma': '🎵', '.m4a': '🎵',
            # Archives
            '.zip': '📦', '.rar': '📦', '.7z': '📦', '.tar': '📦',
            '.gz': '📦', '.bz2': '📦', '.xz': '📦',
            # Code files
            '.py': '🐍', '.js': '📜', '.html': '🌐', '.css': '🎨',
            '.cpp': '⚙️', '.c': '⚙️', '.java': '☕', '.php': '🐘',
            # Executables
            '.exe': '⚙️', '.msi': '📦', '.deb': '📦', '.rpm': '📦',
            '.dmg': '💿', '.app': '📱',
            # System files
            '.dll': '🔧', '.sys': '🔧', '.ini': '⚙️', '.cfg': '⚙️',
            '.reg': '📋', '.log': '📊',
        }
        
        return icon_map.get(ext, '📄')  # Default to document icon

class ImageLoader(QThread):
    """Thread to load and analyze disk image with progress feedback"""
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    partition_found = pyqtSignal(object)
    error_occurred = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, image_path):
        super().__init__()
        self.image_path = os.path.abspath(image_path)
        self.should_stop = False
        self.found_partitions = []

    def run(self):
        try:
            self.status_updated.emit("🔍 Opening image file...")
            logger.info(f"Loading image: {self.image_path}")

            # Open image with progress
            if self.image_path.lower().endswith('.e01'):
                img_info = self.open_ewf_image()
            else:
                img_info = pytsk3.Img_Info(self.image_path)

            self.status_updated.emit("🔍 Analyzing partition structure...")

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
        """Open EWF image with proper path handling and progress"""
        try:
            self.status_updated.emit("🔍 Opening E01 image segments...")
            
            if not os.path.exists(self.image_path):
                raise Exception(f"File does not exist: {self.image_path}")
            
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
            
            logger.info(f"Opening EWF files: {filenames}")
            self.status_updated.emit(f"🔍 Loading {len(filenames)} E01 segments...")
            
            ewf_handle = pyewf.handle()
            ewf_handle.open(filenames)
            
            return EWFImgInfo(ewf_handle)
            
        except Exception as e:
            logger.error(f"Error opening EWF image: {str(e)}")
            raise

    def analyze_partitions(self, img_info, vol_info):
        """Analyze all partitions with progress feedback"""
        all_partitions = []
        for part in vol_info:
            all_partitions.append(part)
        
        logger.info(f"Total partitions found in volume: {len(all_partitions)}")
        
        for i, part in enumerate(all_partitions):
            if self.should_stop:
                break
            
            progress = int((i + 1) / len(all_partitions) * 100)
            self.progress_updated.emit(progress)
            
            desc = "Unknown"
            if part.desc:
                desc = part.desc.decode('utf-8', errors='replace')
            elif hasattr(part, 'type') and part.type:
                desc = f"Type {part.type}"
            
            size_bytes = part.len * 512
            
            self.status_updated.emit(f"🔍 Analyzing partition {i+1}/{len(all_partitions)}: {desc}")
            
            # Check for BitLocker first
            is_bitlocker = BitLockerAnalyzer.detect_bitlocker(img_info, part.start * 512)
            
            if is_bitlocker:
                fs_type = "BitLocker"
                logger.info(f"Partition {i}: BitLocker encrypted at offset {part.start * 512}, size: {size_bytes}")
            else:
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
            
            # Analyze BitLocker if detected
            if is_bitlocker:
                self.status_updated.emit(f"🔒 Analyzing BitLocker volume for partition {i}...")
                partition_info.bitlocker_info = BitLockerAnalyzer.analyze_bitlocker_volume(
                    img_info, part.start * 512, size_bytes
                )
            
            # Only detect VSS for NTFS partitions (and when pyvshadow is available)
            if fs_type.lower() == 'ntfs' and PYVSHADOW_AVAILABLE and not is_bitlocker:
                self.status_updated.emit(f"📂 Detecting Volume Shadow Copies for partition {i}...")
                try:
                    vss_copies = VSSDetector.detect_vss_copies(img_info, part.start * 512)
                    partition_info.vss_copies = vss_copies
                    partition_info.has_real_vss = len(vss_copies) > 0
                    logger.info(f"Found {len(vss_copies)} VSS copies for partition {i}")
                except Exception as e:
                    logger.error(f"Error detecting VSS for partition {i}: {e}")
                    partition_info.vss_copies = []
            
            self.found_partitions.append(partition_info)
            self.partition_found.emit(partition_info)
            logger.info(f"Added partition {i}: {desc}, Size: {size_bytes} bytes, FS: {fs_type}")

    def analyze_single_partition(self, img_info):
        """Analyze single partition with progress feedback"""
        logger.info("No partition table detected, analyzing as single partition")
        
        offsets_to_try = [0, 512, 1024, 2048 * 512, 63 * 512]
        partitions_found = 0
        
        for i, offset in enumerate(offsets_to_try):
            try:
                if offset >= img_info.get_size():
                    continue
                    
                progress = int((i + 1) / len(offsets_to_try) * 100)
                self.progress_updated.emit(progress)
                
                self.status_updated.emit(f"🔍 Trying offset {offset} ({i+1}/{len(offsets_to_try)})...")
                
                # Check for BitLocker first
                is_bitlocker = BitLockerAnalyzer.detect_bitlocker(img_info, offset)
                
                if is_bitlocker:
                    fs_type = "BitLocker"
                else:
                    fs_info = pytsk3.FS_Info(img_info, offset=offset)
                    fs_type = self.get_fs_type_string(fs_info.info.ftype)
                
                partition_info = PartitionInfo(
                    index=partitions_found,
                    description=f"Single Partition at offset {offset}",
                    start_offset=offset,
                    size=img_info.get_size() - offset,
                    fs_type=fs_type
                )
                
                # Analyze BitLocker if detected
                if is_bitlocker:
                    partition_info.bitlocker_info = BitLockerAnalyzer.analyze_bitlocker_volume(
                        img_info, offset, img_info.get_size() - offset
                    )
                
                # Detect VSS for NTFS (non-BitLocker)
                if fs_type.lower() == 'ntfs' and PYVSHADOW_AVAILABLE and not is_bitlocker:
                    self.status_updated.emit("📂 Detecting Volume Shadow Copies...")
                    try:
                        vss_copies = VSSDetector.detect_vss_copies(img_info, offset)
                        partition_info.vss_copies = vss_copies
                        partition_info.has_real_vss = len(vss_copies) > 0
                    except Exception as e:
                        logger.error(f"Error detecting VSS: {e}")
                        partition_info.vss_copies = []
                
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

class LazyDirectoryLoader(QThread):
    """Thread to load directory contents lazily"""
    directory_loaded = pyqtSignal(str, list)
    error_occurred = pyqtSignal(str)

    def __init__(self, fs_info, path, parent=None):
        super().__init__(parent)
        self.fs_info = fs_info
        self.path = path

    def run(self):
        try:
            logger.info(f"Lazy loading directory: {self.path}")
            directory = self.fs_info.open_dir(path=self.path)
            entries = []

            for entry in directory:
                if entry.info.name.name in [b'.', b'..']:
                    continue

                try:
                    filename = entry.info.name.name.decode('utf-8', errors='replace')
                    is_directory = entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR if entry.info.meta else False
                    file_size = entry.info.meta.size if entry.info.meta else 0

                    # Get timestamps
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

                    # Check if directory has subdirectories (not just files)
                    has_subdirectories = False
                    if is_directory:
                        has_subdirectories = self._check_has_subdirectories(os.path.join(self.path, filename).replace('\\', '/'))

                    entry_info = {
                        'name': filename,
                        'path': os.path.join(self.path, filename).replace('\\', '/'),
                        'is_directory': is_directory,
                        'size': file_size,
                        'modified': modified_time,
                        'created': created_time,
                        'accessed': accessed_time,
                        'inode': entry.info.meta.addr if entry.info.meta else 0,
                        'has_children': has_subdirectories  # Only true if has subdirectories
                    }

                    entries.append(entry_info)

                except Exception as e:
                    logger.debug(f"Error processing entry in {self.path}: {str(e)}")
                    continue

            # Sort entries
            entries.sort(key=lambda x: (not x['is_directory'], x['name'].lower()))

            logger.info(f"Lazy loaded {len(entries)} entries from {self.path}")
            self.directory_loaded.emit(self.path, entries)

        except Exception as e:
            logger.error(f"Error lazy loading directory {self.path}: {str(e)}")
            self.error_occurred.emit(f"Error loading directory {self.path}: {str(e)}")

    def _check_has_subdirectories(self, path):
        """Check if directory has subdirectories (not just files)"""
        try:
            directory = self.fs_info.open_dir(path=path)
            for entry in directory:
                if entry.info.name.name in [b'.', b'..']:
                    continue
                # Check if this entry is a directory
                if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    return True
            return False
        except:
            return False

class FilesystemLoader(QThread):
    """Thread to load filesystem structure with lazy loading"""
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    directory_loaded = pyqtSignal(str, list)
    error_occurred = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, image_path, partition_info, vss_index=None):
        super().__init__()
        self.image_path = os.path.abspath(image_path)
        self.partition_info = partition_info
        self.vss_index = vss_index
        self.should_stop = False
        self.fs_info = None
        self.img_info = None

    def run(self):
        try:
            self.status_updated.emit("🔍 Opening filesystem...")
            logger.info(f"Loading filesystem from {self.image_path} at offset {self.partition_info.start_offset}")

            # Open image
            if self.image_path.lower().endswith('.e01'):
                self.img_info = self.open_ewf_image()
            else:
                self.img_info = pytsk3.Img_Info(self.image_path)

            # Handle BitLocker volumes
            if self.partition_info.bitlocker_info.is_encrypted:
                if not self.partition_info.bitlocker_info.is_unlocked:
                    self.error_occurred.emit("BitLocker volume is not unlocked. Please unlock it first.")
                    return
                
                self.status_updated.emit("🔓 Accessing decrypted BitLocker volume...")
                # Use decrypted volume access for BitLocker
                decrypted_access = DecryptedVolumeAccess(self.partition_info.bitlocker_info.bde_volume)
                self.fs_info = pytsk3.FS_Info(decrypted_access)
                
            elif self.vss_index is not None and PYVSHADOW_AVAILABLE:
                # VSS access
                self.status_updated.emit(f"📂 Accessing VSS copy {self.vss_index}...")
                self.fs_info = self._get_vss_filesystem()
                if not self.fs_info:
                    self.error_occurred.emit(f"Failed to access VSS copy {self.vss_index}")
                    return
            else:
                # Regular filesystem
                self.fs_info = pytsk3.FS_Info(self.img_info, offset=self.partition_info.start_offset)

            self.status_updated.emit("📁 Loading directory structure...")

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

    def _get_vss_filesystem(self):
        """Get VSS filesystem for the specified index"""
        if not PYVSHADOW_AVAILABLE or self.vss_index is None:
            return None

        try:
            # Create VShadow volume
            volume_object = VShadowVolume(self.img_info, self.partition_info.start_offset)
            
            # Open the volume
            vshadow_volume = pyvshadow.volume()
            vshadow_volume.open_file_object(volume_object)
            
            # Get the specified store
            store = vshadow_volume.get_store(self.vss_index)
            
            # Create a pytsk3 image using the store
            store_img = VShadowImgInfo(store)
            
            # Create a filesystem object
            fs_info = pytsk3.FS_Info(store_img)
            
            return fs_info
            
        except Exception as e:
            logger.error(f"Error getting VSS filesystem: {str(e)}")
            return None

    def load_directory(self, path):
        """Load directory contents with comprehensive metadata"""
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

                    # Get comprehensive MACB timestamps
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

                    # Check if directory has subdirectories (not just files)
                    has_subdirectories = False
                    if is_directory:
                        has_subdirectories = self._check_has_subdirectories(os.path.join(path, filename).replace('\\', '/'))

                    entry_info = {
                        'name': filename,
                        'path': os.path.join(path, filename).replace('\\', '/'),
                        'is_directory': is_directory,
                        'size': file_size,
                        'modified': modified_time,
                        'created': created_time,
                        'accessed': accessed_time,
                        'inode': entry.info.meta.addr if entry.info.meta else 0,
                        'has_children': has_subdirectories  # Only true if has subdirectories
                    }

                    entries.append(entry_info)

                except Exception as e:
                    logger.debug(f"Error processing entry: {str(e)}")
                    continue

            # Sort entries: directories first, then files, both alphabetically
            entries.sort(key=lambda x: (not x['is_directory'], x['name'].lower()))

            logger.info(f"Loaded {len(entries)} entries from {path}")
            self.directory_loaded.emit(path, entries)

        except Exception as e:
            logger.error(f"Error loading directory {path}: {str(e)}")
            self.error_occurred.emit(f"Error loading directory {path}: {str(e)}")

    def _check_has_subdirectories(self, path):
        """Check if directory has subdirectories (not just files)"""
        try:
            directory = self.fs_info.open_dir(path=path)
            for entry in directory:
                if entry.info.name.name in [b'.', b'..']:
                    continue
                # Check if this entry is a directory
                if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    return True
            return False
        except:
            return False

    def stop(self):
        self.should_stop = True

class ForensicExplorerMainWindow(QMainWindow):
    """Improved forensic explorer with better UI and functionality"""
    def __init__(self):
        super().__init__()
        self.current_image_path = None
        self.current_partitions = []
        self.current_filesystem_loader = None
        self.current_img_info = None
        self.current_fs_info = None
        self.current_directory_data = {}
        self.current_path = "/"
        self.loading_items = {}  # Track items currently being loaded
        self.init_ui()
        logger.info("VSC Explorer initialized")

    def init_ui(self):
        """Initialize improved UI with proper alignment and visibility"""
        self.setWindowTitle("VSC Explorer v1.0")
        self.setGeometry(100, 100, 1400, 900)
        
        # Set window icon if available
        if os.path.exists("logo.png"):
            self.setWindowIcon(QIcon("logo.png"))

        # Improved stylesheet with proper alignment fixes
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QWidget {
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 11px;
            }
            QComboBox {
                background-color: white;
                border: 2px solid #ddd;
                border-radius: 6px;
                padding: 6px;
                min-height: 20px;
                color: #333;
                font-weight: bold;
                font-size: 11px;
            }
            QComboBox:focus {
                border-color: #4CAF50;
            }
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            QComboBox::down-arrow {
                image: none;
                border: none;
                width: 12px;
                height: 12px;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px 14px;
                border-radius: 6px;
                font-weight: bold;
                min-width: 80px;
                font-size: 12px;
                min-height: 28px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3e8e41;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
            QTreeWidget {
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 6px;
                font-size: 11px;
            }
            QTreeWidget::item {
                padding: 3px;
                border-bottom: 1px solid #f0f0f0;
                min-height: 20px;
            }
            QTreeWidget::item:selected {
                background-color: #e3f2fd;
                color: #1976d2;
            }
            QTableWidget {
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 6px;
                gridline-color: #f0f0f0;
                font-size: 11px;
            }
            QTableWidget::item {
                padding: 4px 6px;
                border-bottom: 1px solid #f0f0f0;
                min-height: 18px;
            }
            QTableWidget::item:selected {
                background-color: #e3f2fd;
                color: #1976d2;
            }
            QHeaderView::section {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                padding: 6px;
                font-weight: bold;
                color: #495057;
                font-size: 11px;
                min-height: 20px;
            }
            QProgressBar {
                border: 1px solid #ddd;
                border-radius: 6px;
                text-align: center;
                background-color: #f0f0f0;
                font-size: 10px;
                min-height: 16px;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 5px;
            }
            QStatusBar {
                background-color: #f8f9fa;
                border-top: 1px solid #dee2e6;
                color: #495057;
                font-size: 11px;
                min-height: 24px;
            }
            QLabel {
                font-size: 11px;
                padding: 2px;
            }
            QLineEdit {
                padding: 6px;
                border: 2px solid #ddd;
                border-radius: 6px;
                font-size: 11px;
                background-color: white;
                min-height: 18px;
            }
            QLineEdit:focus {
                border-color: #4CAF50;
            }
        """)

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main vertical layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(8)

        # Create toolbar with fixed alignment
        self.create_toolbar(main_layout)

        # Create current path display with fixed alignment
        self.create_path_display(main_layout)

        # Create main content with splitter
        self.create_main_content(main_layout)

        # Create status bar
        self.create_status_bar()

    def create_toolbar(self, parent_layout):
        """Create properly aligned toolbar"""
        # Toolbar container with fixed height
        toolbar_widget = QWidget()
        toolbar_widget.setFixedHeight(80)  # Increased height for better alignment
        toolbar_widget.setStyleSheet("""
            QWidget {
                background-color: white;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
            }
        """)
        
        # Main horizontal layout
        toolbar_layout = QHBoxLayout(toolbar_widget)
        toolbar_layout.setContentsMargins(15, 15, 15, 15)
        toolbar_layout.setSpacing(15)

        # Open Image button
        self.open_btn = QPushButton("📁 Open Image")
        self.open_btn.setFixedSize(130, 45)
        self.open_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                font-size: 13px;
                font-weight: bold;
                padding: 12px 16px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        self.open_btn.clicked.connect(self.open_image)
        toolbar_layout.addWidget(self.open_btn)

        # Separator
        sep1 = QFrame()
        sep1.setFrameShape(QFrame.VLine)
        sep1.setFrameShadow(QFrame.Sunken)
        sep1.setStyleSheet("color: #ddd;")
        sep1.setFixedHeight(40)
        toolbar_layout.addWidget(sep1)

        # Partition selection group
        partition_layout = QVBoxLayout()
        partition_layout.setSpacing(5)
        
        partition_label = QLabel("🗂️ Partition:")
        partition_label.setFixedHeight(20)
        partition_label.setStyleSheet("""
            QLabel {
                font-weight: bold;
                font-size: 12px;
                color: #333;
                padding: 2px 0px;
            }
        """)

        partition_layout.addWidget(partition_label)
        
        self.partition_combo = QComboBox()
        self.partition_combo.setFixedSize(320, 38)
        self.partition_combo.currentIndexChanged.connect(self.partition_changed)
        self.partition_combo.setEnabled(False)
        partition_layout.addWidget(self.partition_combo)
        
        toolbar_layout.addLayout(partition_layout)

        # BitLocker unlock button
        self.unlock_bitlocker_btn = QPushButton("🔒 Unlock")
        self.unlock_bitlocker_btn.setFixedSize(120, 45)
        self.unlock_bitlocker_btn.clicked.connect(self.unlock_bitlocker)
        self.unlock_bitlocker_btn.setEnabled(False)
        toolbar_layout.addWidget(self.unlock_bitlocker_btn)

        # VSS selection
        self.vss_combo = QComboBox()
        self.vss_combo.setFixedSize(280, 38)
        self.vss_combo.currentIndexChanged.connect(self.vss_changed)
        self.vss_combo.setEnabled(False)
        toolbar_layout.addWidget(self.vss_combo)

        # Load filesystem button
        self.load_fs_btn = QPushButton("📁 Load FS")
        self.load_fs_btn.setFixedSize(120, 45)
        self.load_fs_btn.clicked.connect(self.load_filesystem)
        self.load_fs_btn.setEnabled(False)
        self.load_fs_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-size: 13px;
                font-weight: bold;
                padding: 12px 16px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        toolbar_layout.addWidget(self.load_fs_btn)

        # Stretch and progress bar
        toolbar_layout.addStretch()
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedSize(180, 32)
        toolbar_layout.addWidget(self.progress_bar)

        parent_layout.addWidget(toolbar_widget)

    def create_path_display(self, parent_layout):
        """Create properly aligned path display with enhanced export buttons"""
        # Container (outer border with increased size)
        path_widget = QWidget()
        path_widget.setFixedHeight(80)  # Increased for better spacing
        path_widget.setStyleSheet("""
            QWidget {
                background-color: #e8f4fd;
                border: 2px solid #b3d9ff;  /* Increased border width */
                border-radius: 8px;         /* Increased radius */
            }
        """)

        # Main row
        path_layout = QHBoxLayout(path_widget)
        path_layout.setContentsMargins(16, 12, 16, 12)  # Increased margins
        path_layout.setSpacing(12)
        path_layout.setAlignment(Qt.AlignVCenter)

        # Left: Location label + path
        location_layout = QHBoxLayout()
        location_layout.setSpacing(10)
        location_layout.setAlignment(Qt.AlignVCenter)

        location_label = QLabel("📍 Location:")
        location_label.setFixedHeight(32)
        location_label.setStyleSheet("""
            QLabel {
                font-weight: bold;
                color: #333333;
                font-size: 12px;
            }
        """)
        location_layout.addWidget(location_label)

        self.path_label = QLineEdit("/")
        self.path_label.setReadOnly(True)
        self.path_label.setFixedHeight(32)
        self.path_label.setMinimumWidth(280)
        self.path_label.setStyleSheet("""
            QLineEdit {
                font-family: 'Courier New', monospace;
                font-weight: bold;
                color: #1976d2;
                background-color: white;
                border: 1px solid #ddd;
                padding: 8px 12px;
                border-radius: 6px;
                font-size: 12px;
            }
        """)
        location_layout.addWidget(self.path_label, 1)

        path_layout.addLayout(location_layout, 1)
        path_layout.addStretch()

        # Right: Export buttons panel with enhanced styling
        buttons_panel = QWidget()
        buttons_panel.setFixedHeight(60)
        buttons_panel.setMaximumWidth(340)  # Increased width
        buttons_panel.setStyleSheet("""
            QWidget {
                background-color: #dfeffd;
                border: 2px solid #c5defa;  /* Increased border */
                border-radius: 8px;         /* Increased radius */
            }
        """)

        buttons_layout = QHBoxLayout(buttons_panel)
        buttons_layout.setContentsMargins(12, 0, 12, 6)  # Better padding
        buttons_layout.setSpacing(10)
        buttons_layout.setAlignment(Qt.AlignVCenter)

        # Export Selected with improved styling
        self.export_selected_btn = QPushButton("📤 Export Selected")
        self.export_selected_btn.setFixedHeight(32)
        self.export_selected_btn.setMinimumWidth(155)
        self.export_selected_btn.clicked.connect(self.export_selected_files)
        self.export_selected_btn.setEnabled(False)
        self.export_selected_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-size: 11px;
                font-weight: bold;
                padding: 6px 14px;
                border-radius: 6px;
                border: none;
            }
            QPushButton:hover { background-color: #45a049; }
            QPushButton:disabled { background-color: #cccccc; color: #666666; }
        """)
        buttons_layout.addWidget(self.export_selected_btn)

        # Export All with improved styling
        self.export_all_btn = QPushButton("📦 Export All")
        self.export_all_btn.setFixedHeight(32)
        self.export_all_btn.setMinimumWidth(125)
        self.export_all_btn.clicked.connect(self.export_all_files)
        self.export_all_btn.setEnabled(False)
        self.export_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-size: 11px;
                font-weight: bold;
                padding: 6px 14px;
                border-radius: 6px;
                border: none;
            }
            QPushButton:hover { background-color: #45a049; }
            QPushButton:disabled { background-color: #cccccc; color: #666666; }
        """)
        buttons_layout.addWidget(self.export_all_btn)

        # Add the buttons panel
        path_layout.addWidget(buttons_panel, 0, Qt.AlignRight | Qt.AlignVCenter)

        parent_layout.addWidget(path_widget)

    def create_main_content(self, parent_layout):
        """Create main content area with improved visibility"""
        # Main splitter - horizontal
        main_splitter = QSplitter(Qt.Horizontal)
        main_splitter.setChildrenCollapsible(False)

        # Left panel - Tree view
        left_panel = QWidget()
        left_panel.setFixedWidth(350)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(4, 4, 4, 4)
        left_layout.setSpacing(4)

        # Tree header
        tree_header = QLabel("🗂️ Directory Structure")
        tree_header.setStyleSheet("""
            QLabel {
                background-color: #f8f9fa;
                padding: 8px;
                font-weight: bold;
                border: 1px solid #dee2e6;
                border-radius: 6px 6px 0 0;
                color: #495057;
                font-size: 12px;
                min-height: 16px;
            }
        """)
        left_layout.addWidget(tree_header)

        # Tree widget
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderHidden(True)
        self.tree_widget.itemExpanded.connect(self.on_tree_expanded)
        self.tree_widget.itemClicked.connect(self.on_tree_clicked)
        self.tree_widget.itemDoubleClicked.connect(self.on_tree_double_clicked)
        self.tree_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_widget.customContextMenuRequested.connect(self.show_tree_context_menu)
        self.tree_widget.setSelectionMode(QAbstractItemView.SingleSelection)
        left_layout.addWidget(self.tree_widget)

        main_splitter.addWidget(left_panel)

        # Right panel - File view
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(4, 4, 4, 4)
        right_layout.setSpacing(4)

        # File view header
        file_header = QLabel("📋 File Details")
        file_header.setStyleSheet("""
            QLabel {
                background-color: #f8f9fa;
                padding: 8px;
                font-weight: bold;
                border: 1px solid #dee2e6;
                border-radius: 6px 6px 0 0;
                color: #495057;
                font-size: 12px;
                min-height: 16px;
            }
        """)
        right_layout.addWidget(file_header)

        # File table
        self.file_table = QTableWidget()
        self.file_table.setColumnCount(6)
        self.file_table.setHorizontalHeaderLabels(['Name', 'Size', 'Type', 'Modified', 'Created', 'Accessed'])

        # Configure table header
        header = self.file_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)  # Name column stretches
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Size
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Type
        header.setSectionResizeMode(3, QHeaderView.Interactive)  # Modified
        header.setSectionResizeMode(4, QHeaderView.Interactive)  # Created
        header.setSectionResizeMode(5, QHeaderView.Interactive)  # Accessed

        # Set column widths
        self.file_table.setColumnWidth(1, 90)  # Size
        self.file_table.setColumnWidth(2, 70)  # Type
        self.file_table.setColumnWidth(3, 150)  # Modified
        self.file_table.setColumnWidth(4, 150)  # Created
        self.file_table.setColumnWidth(5, 150)  # Accessed

        # Configure table behavior
        self.file_table.setAlternatingRowColors(True)
        self.file_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.file_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.file_table.setSortingEnabled(True)
        self.file_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_table.customContextMenuRequested.connect(self.show_file_context_menu)
        self.file_table.itemDoubleClicked.connect(self.on_file_double_clicked)
        self.file_table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        # Set row height
        self.file_table.verticalHeader().setDefaultSectionSize(24)

        right_layout.addWidget(self.file_table)
        main_splitter.addWidget(right_panel)

        # Set splitter proportions
        main_splitter.setSizes([350, 1050])

        parent_layout.addWidget(main_splitter)

    def create_status_bar(self):
        """Create enhanced status bar"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        self.status_label = QLabel("🔍 Ready - Open a forensic image to begin analysis")
        self.status_label.setStyleSheet("font-weight: bold; color: #495057; font-size: 11px; padding: 2px;")
        self.status_bar.addWidget(self.status_label)

    def update_path_display(self, path):
        """Update the current path display"""
        self.current_path = path
        display_path = path if path != "/" else "/ (Root)"
        self.path_label.setText(display_path)

    def open_image(self):
        """Open disk image file"""
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(
            self,
            "Open Forensic Disk Image",
            "",
            "Disk Images (*.dd *.raw *.img *.e01 *.ex01);;All Files (*)"
        )

        if file_path:
            self.current_image_path = os.path.abspath(file_path)
            self.status_label.setText(f"🔍 Loading image: {os.path.basename(file_path)}")
            logger.info(f"Selected image: {self.current_image_path}")

            # Clear previous data
            self.partition_combo.clear()
            self.vss_combo.clear()
            self.tree_widget.clear()
            self.file_table.setRowCount(0)
            self.current_partitions = []
            self.current_directory_data = {}
            self.loading_items = {}
            
            # Reset button states
            self.unlock_bitlocker_btn.setEnabled(False)
            self.load_fs_btn.setEnabled(False)
            self.export_selected_btn.setEnabled(False)
            self.export_all_btn.setEnabled(False)
            
            self.update_path_display("/")
            self.load_image()

    def load_image(self):
        """Load and analyze image with progress feedback"""
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
        """Add partition to dropdown with improved display"""
        self.current_partitions.append(partition_info)
        size_mb = partition_info.size / (1024 * 1024)

        # Create display text with proper icons
        if partition_info.bitlocker_info.is_encrypted:
            if partition_info.bitlocker_info.is_unlocked:
                lock_icon = "🔓"
                bitlocker_status = " [BitLocker Unlocked]"
            else:
                lock_icon = "🔒"
                bitlocker_status = " [BitLocker Encrypted]"
        else:
            lock_icon = "💾"
            bitlocker_status = ""

        display_text = f"{lock_icon} P{partition_info.index}: {partition_info.fs_type} ({size_mb:,.0f}MB){bitlocker_status}"
        self.partition_combo.addItem(display_text, partition_info)
        logger.info(f"Added partition: {display_text}")

    def show_error(self, error_message):
        """Show error message with better styling"""
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)
        msg.setWindowTitle("VSC Explorer - Error")
        msg.setText("An error occurred:")
        msg.setDetailedText(error_message)
        msg.setStyleSheet("""
            QMessageBox {
                background-color: #f8f9fa;
                font-size: 12px;
            }
            QMessageBox QPushButton {
                background-color: #dc3545;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
                min-width: 70px;
                font-size: 11px;
            }
            QMessageBox QPushButton:hover {
                background-color: #c82333;
            }
        """)
        msg.exec_()
        logger.error(error_message)

    def image_load_finished(self):
        """Image loading finished"""
        self.progress_bar.setVisible(False)
        self.open_btn.setEnabled(True)

        if self.current_partitions:
            self.partition_combo.setEnabled(True)
            self.status_label.setText(f"✅ Found {len(self.current_partitions)} partitions - Select partition for analysis")
        else:
            self.status_label.setText("⚠️ No valid partitions found")

    def partition_changed(self):
        """Handle partition selection change with comprehensive VSS display and proper refresh"""
        partition_info = self.partition_combo.currentData()
        if not partition_info:
            self.load_fs_btn.setEnabled(False)
            self.unlock_bitlocker_btn.setEnabled(False)
            self.vss_combo.clear()
            self.vss_combo.setEnabled(False)
            return

        # Clear current filesystem data when switching partitions
        self.tree_widget.clear()
        self.file_table.setRowCount(0)
        self.current_directory_data = {}
        self.loading_items = {}
        self.current_fs_info = None
        self.current_img_info = None
        self.update_path_display("/")
        self.export_selected_btn.setEnabled(False)
        self.export_all_btn.setEnabled(False)

        self.vss_combo.clear()
        self.vss_combo.setEnabled(False)
        self.load_fs_btn.setEnabled(False)

        # BitLocker logic
        if partition_info.bitlocker_info.is_encrypted:
            if partition_info.bitlocker_info.is_unlocked:
                self.unlock_bitlocker_btn.setText("🔓 Unlocked")
                self.unlock_bitlocker_btn.setEnabled(False)
                self.unlock_bitlocker_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #28a745;
                        color: white;
                        font-weight: bold;
                        font-size: 12px;
                        padding: 8px 12px;
                    }
                """)
                self.load_fs_btn.setEnabled(True)
                
                # Initialize VSS combo for unlocked BitLocker
                self.vss_combo.clear()
                self.vss_combo.addItem("🔍 Main Volume", None)
                self.vss_combo.setEnabled(True)
                
                # Refresh VSS for BitLocker if needed
                self.refresh_vss_for_partition(partition_info)
                
            else:
                self.unlock_bitlocker_btn.setText("🔒 Unlock")
                self.unlock_bitlocker_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #dc3545;
                        color: white;
                        font-weight: bold;
                        font-size: 12px;
                        padding: 8px 12px;
                    }
                """)
                self.unlock_bitlocker_btn.setEnabled(True)
                self.load_fs_btn.setEnabled(False)
                self.vss_combo.clear()
                self.vss_combo.addItem("🔒 BitLocker Locked", None)
                self.vss_combo.setEnabled(False)
        else:
            # Non-BitLocker partition
            self.unlock_bitlocker_btn.setText("🔒 Unlock")
            self.unlock_bitlocker_btn.setEnabled(False)
            self.unlock_bitlocker_btn.setStyleSheet("""
                QPushButton {
                    background-color: #cccccc;
                    color: #666666;
                    font-weight: bold;
                    font-size: 12px;
                    padding: 8px 12px;
                }
            """)
            self.load_fs_btn.setEnabled(True)
            
            # Initialize VSS combo for regular partitions
            self.vss_combo.clear()
            self.vss_combo.addItem("🔍 Main Volume", None)
            
            if partition_info.fs_type.lower() == 'ntfs' and PYVSHADOW_AVAILABLE:
                self.vss_combo.setEnabled(True)
                # Refresh VSS for regular NTFS partition
                self.refresh_vss_for_partition(partition_info)
            else:
                self.vss_combo.setEnabled(False)

        logger.info(f"Selected partition: {str(partition_info)}")
        logger.info(f"BitLocker encrypted: {partition_info.bitlocker_info.is_encrypted}")
        logger.info(f"Available VSS copies: {len(partition_info.vss_copies)}")

    def refresh_vss_for_partition(self, partition_info):
        """Refresh VSS for the given partition"""
        try:
            # Get current image info for VSS detection
            if not self.current_image_path:
                return
                
            # Open image for VSS detection
            if self.current_image_path.lower().endswith('.e01'):
                # Handle EWF images
                try:
                    directory = os.path.dirname(self.current_image_path)
                    filename = os.path.basename(self.current_image_path)
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
                        filenames = [self.current_image_path]
                    
                    ewf_handle = pyewf.handle()
                    ewf_handle.open(filenames)
                    temp_img_info = EWFImgInfo(ewf_handle)
                except Exception as e:
                    logger.error(f"Error opening EWF for VSS: {e}")
                    return
            else:
                temp_img_info = pytsk3.Img_Info(self.current_image_path)

            # Detect VSS copies
            if partition_info.bitlocker_info.is_encrypted and partition_info.bitlocker_info.is_unlocked:
                # For unlocked BitLocker
                vss_copies = VSSDetector.detect_vss_copies(
                    partition_info, partition_info.start_offset, is_bitlocker=True
                )
            elif not partition_info.bitlocker_info.is_encrypted and partition_info.fs_type.lower() == 'ntfs':
                # For regular NTFS
                vss_copies = VSSDetector.detect_vss_copies(
                    temp_img_info, partition_info.start_offset, is_bitlocker=False
                )
            else:
                vss_copies = []

            # Update partition info and combo
            partition_info.vss_copies = vss_copies
            
            # Refresh VSS combo
            current_selection = self.vss_combo.currentText()
            self.vss_combo.clear()
            self.vss_combo.addItem("🔍 Main Volume", None)
            
            if vss_copies:
                for i, vss_copy in enumerate(vss_copies):
                    display_text = f"📂 VSS {i+1}: {vss_copy.creation_time_utc}"
                    self.vss_combo.addItem(display_text, vss_copy)
                
                # Try to restore previous selection
                for i in range(self.vss_combo.count()):
                    if self.vss_combo.itemText(i) == current_selection:
                        self.vss_combo.setCurrentIndex(i)
                        break
                        
                self.status_label.setText(f"✅ Found {len(vss_copies)} Volume Shadow Copies")
            else:
                self.status_label.setText("✅ No Volume Shadow Copies found")
                
        except Exception as e:
            logger.error(f"Error refreshing VSS: {e}")
            self.status_label.setText("⚠️ VSS detection completed with warnings")

    def unlock_bitlocker(self):
        """Unlock BitLocker volume with improved UI and UI refreshes"""
        partition_info = self.partition_combo.currentData()
        if not partition_info or not partition_info.bitlocker_info.is_encrypted:
            return

        # Show BitLocker credentials dialog
        dialog = BitLockerCredentialsDialog(partition_info.bitlocker_info, self)
        if dialog.exec_() == QDialog.Accepted:
            password = dialog.password
            recovery_key = dialog.recovery_key
            if not password and not recovery_key:
                QMessageBox.warning(self, "Warning", "Please enter either a password or recovery key.")
                return
            
            self.status_label.setText("🔓 Unlocking BitLocker volume...")
            self.unlock_bitlocker_btn.setEnabled(False)
            QApplication.processEvents()

            success = BitLockerAnalyzer.unlock_bitlocker_volume(
                partition_info.bitlocker_info, password, recovery_key
            )

            if success:
                QMessageBox.information(self, "BitLocker Unlock Success", 
                    "🔓 BitLocker volume unlocked successfully!\nThe encrypted volume is now accessible for analysis.")
                self.status_label.setText("✅ BitLocker volume unlocked - Ready for analysis")
                
                # Update the combo display to show unlocked status
                self.partition_combo.clear()
                for i, part_info in enumerate(self.current_partitions):
                    size_mb = part_info.size / (1024 * 1024)
                    if part_info.bitlocker_info.is_encrypted:
                        if part_info.bitlocker_info.is_unlocked:
                            lock_icon = "🔓"
                            bitlocker_status = " [BitLocker Unlocked]"
                        else:
                            lock_icon = "🔒"
                            bitlocker_status = " [BitLocker Encrypted]"
                    else:
                        lock_icon = "💾"
                        bitlocker_status = ""
                    
                    display_text = f"{lock_icon} P{part_info.index}: {part_info.fs_type} ({size_mb:,.0f}MB){bitlocker_status}"
                    self.partition_combo.addItem(display_text, part_info)
                    
                    if part_info == partition_info:
                        self.partition_combo.setCurrentIndex(i)
                
                self.partition_changed()  # Refresh the UI state
                
            else:
                QMessageBox.critical(self, "BitLocker Unlock Failed", 
                    "❌ BitLocker unlock failed - Verify credentials")
                self.unlock_bitlocker_btn.setEnabled(True)
                self.status_label.setText("❌ BitLocker unlock failed - Verify credentials")

    def vss_changed(self):
        """Handle VSS selection change with detailed info"""
        vss_data = self.vss_combo.currentData()
        if vss_data:
            if hasattr(vss_data, "creation_time_utc"):
                self.status_label.setText(f"📂 Selected VSS: {vss_data.creation_time_utc} (ID: {vss_data.shadow_copy_id[:8]}...)")
            else:
                self.status_label.setText("🔍 Main volume selected")
        else:
            self.status_label.setText("🔍 Main volume selected")

    def load_filesystem(self):
        """Load filesystem structure with proper validation"""
        partition_info = self.partition_combo.currentData()
        vss_data = self.vss_combo.currentData()

        if not partition_info:
            QMessageBox.warning(self, "Warning", "Please select a partition first.")
            return

        if partition_info.bitlocker_info.is_encrypted and not partition_info.bitlocker_info.is_unlocked:
            QMessageBox.warning(self, "Warning", "Please unlock the BitLocker volume first.")
            return

        self.tree_widget.clear()
        self.file_table.setRowCount(0)
        self.current_directory_data = {}
        self.loading_items = {}
        self.update_path_display("/")

        vss_index = vss_data.index if vss_data and hasattr(vss_data, 'index') else None
        logger.info(
            f"Loading filesystem for partition {partition_info.index} at offset {partition_info.start_offset}"
        )

        self.current_filesystem_loader = FilesystemLoader(
            self.current_image_path, partition_info, vss_index
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
        """Populate tree with root directory and lazy loading support"""
        if path == "/":
            logger.info(f"Populating root directory with {len(entries)} entries")
            self.current_directory_data[path] = entries

            if self.current_filesystem_loader:
                self.current_img_info = self.current_filesystem_loader.img_info
                self.current_fs_info = self.current_filesystem_loader.fs_info

            # Add directories to tree (lazy loading) - only show dropdown if has subdirectories
            for entry in entries:
                if entry['is_directory']:
                    item = QTreeWidgetItem(self.tree_widget)
                    icon = FileIconProvider.get_file_icon(entry['name'], True)
                    item.setText(0, f"{icon} {entry['name']}")
                    item.setData(0, Qt.UserRole, entry)

                    # Only add dummy child if directory has subdirectories (not just files)
                    if entry.get('has_children', False):
                        dummy = QTreeWidgetItem(item)
                        dummy.setText(0, "Loading...")

            self.populate_file_table(entries)
            self.update_path_display("/")

            # Enable export buttons
            self.export_selected_btn.setEnabled(True)
            self.export_all_btn.setEnabled(True)

    def populate_file_table(self, entries):
        """Populate file table with improved icons and timestamp display"""
        self.file_table.setRowCount(len(entries))

        for row, entry in enumerate(entries):
            # Name column with appropriate icon
            name_item = QTableWidgetItem()
            icon = FileIconProvider.get_file_icon(entry['name'], entry['is_directory'])
            name_item.setText(f"{icon} {entry['name']}")
            name_item.setData(Qt.UserRole, entry)
            name_item.setFlags(name_item.flags() & ~Qt.ItemIsEditable)
            self.file_table.setItem(row, 0, name_item)

            # Size column
            if entry['is_directory']:
                size_text = "—"
            else:
                size = entry['size']
                if size > 1024 * 1024 * 1024:  # GB
                    size_text = f"{size / (1024 * 1024 * 1024):.1f} GB"
                elif size > 1024 * 1024:  # MB
                    size_text = f"{size / (1024 * 1024):.1f} MB"
                elif size > 1024:  # KB
                    size_text = f"{size / 1024:.1f} KB"
                else:
                    size_text = f"{size} bytes"

            size_item = QTableWidgetItem(size_text)
            size_item.setFlags(size_item.flags() & ~Qt.ItemIsEditable)
            size_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.file_table.setItem(row, 1, size_item)

            # Type column
            if entry['is_directory']:
                type_text = "Folder"
            else:
                ext = os.path.splitext(entry['name'])[1].upper()
                type_text = f"{ext[1:]} File" if ext else "File"

            type_item = QTableWidgetItem(type_text)
            type_item.setFlags(type_item.flags() & ~Qt.ItemIsEditable)
            self.file_table.setItem(row, 2, type_item)

            # Timestamp columns with proper formatting
            timestamps = [
                entry.get('modified'),  # Modified
                entry.get('created'),   # Created
                entry.get('accessed')   # Accessed
            ]

            for col_offset, timestamp in enumerate(timestamps, 3):
                if timestamp:
                    timestamp_text = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    timestamp_text = "—"

                timestamp_item = QTableWidgetItem(timestamp_text)
                timestamp_item.setFlags(timestamp_item.flags() & ~Qt.ItemIsEditable)
                self.file_table.setItem(row, col_offset, timestamp_item)

    def filesystem_load_finished(self):
        """Filesystem loading finished"""
        self.progress_bar.setVisible(False)
        self.load_fs_btn.setEnabled(True)
        self.status_label.setText("✅ Filesystem loaded successfully - Ready for analysis")

    def on_tree_expanded(self, item):
        """Handle lazy loading when tree item is expanded"""
        if not item:
            return

        entry_data = item.data(0, Qt.UserRole)
        if not entry_data:
            return

        path = entry_data['path']

        # Check if this item has dummy children that need to be loaded
        if item.childCount() == 1:
            child = item.child(0)
            if child and child.text(0) == "Loading...":
                # Check if we're already loading this path
                if path in self.loading_items:
                    return

                # Mark as loading
                self.loading_items[path] = item

                # Start lazy loading
                self.lazy_loader = LazyDirectoryLoader(self.current_fs_info, path, self)
                self.lazy_loader.directory_loaded.connect(self.on_lazy_directory_loaded)
                self.lazy_loader.error_occurred.connect(self.on_lazy_load_error)
                self.lazy_loader.start()

    def on_lazy_directory_loaded(self, path, entries):
        """Handle lazy loaded directory contents"""
        if path in self.loading_items:
            item = self.loading_items[path]
            del self.loading_items[path]

            # Remove loading dummy
            item.takeChildren()

            # Store in cache
            self.current_directory_data[path] = entries

            # Add directories to tree - only show dropdown if has subdirectories
            for entry in entries:
                if entry['is_directory']:
                    child_item = QTreeWidgetItem(item)
                    icon = FileIconProvider.get_file_icon(entry['name'], True)
                    child_item.setText(0, f"{icon} {entry['name']}")
                    child_item.setData(0, Qt.UserRole, entry)

                    # Only add dummy child if has subdirectories (not just files)
                    if entry.get('has_children', False):
                        dummy = QTreeWidgetItem(child_item)
                        dummy.setText(0, "Loading...")

    def on_lazy_load_error(self, error_message):
        """Handle lazy loading errors"""
        logger.error(f"Lazy loading error: {error_message}")
        # Remove loading indicators
        for path, item in list(self.loading_items.items()):
            item.takeChildren()  # Remove "Loading..." indicator
            del self.loading_items[path]

    def on_tree_clicked(self, item, column):
        """Handle tree item click to show directory contents"""
        if not item:
            return

        entry_data = item.data(0, Qt.UserRole)
        if entry_data:
            path = entry_data['path']

            # Update file table with directory contents if cached
            if path in self.current_directory_data:
                self.populate_file_table(self.current_directory_data[path])
                self.update_path_display(path)
            else:
                # Load directory contents if not cached
                if path not in self.loading_items and self.current_fs_info:
                    self.loading_items[path] = item
                    self.lazy_loader = LazyDirectoryLoader(self.current_fs_info, path, self)
                    self.lazy_loader.directory_loaded.connect(self.on_lazy_click_loaded)
                    self.lazy_loader.error_occurred.connect(self.on_lazy_load_error)
                    self.lazy_loader.start()

    def on_lazy_click_loaded(self, path, entries):
        """Handle lazy loaded directory for click navigation"""
        if path in self.loading_items:
            del self.loading_items[path]

        # Store in cache
        self.current_directory_data[path] = entries

        # Update file table
        self.populate_file_table(entries)
        self.update_path_display(path)

    def on_tree_double_clicked(self, item, column):
        """Handle tree item double click"""
        self.on_tree_clicked(item, column)

    def on_file_double_clicked(self, item):
        """Enhanced file table double click to navigate into directories"""
        if not item:
            return

        entry_data = item.data(Qt.UserRole)
        if entry_data and entry_data['is_directory']:
            path = entry_data['path']
            
            # Check if directory contents are already cached
            if path in self.current_directory_data:
                # Directly navigate to cached directory
                self.populate_file_table(self.current_directory_data[path])
                self.update_path_display(path)
                
                # Also update tree selection if possible
                self.update_tree_selection(path)
            else:
                # Load directory contents if not cached
                if path not in self.loading_items and self.current_fs_info:
                    self.loading_items[path] = None  # Mark as loading
                    self.status_label.setText(f"🔍 Loading directory: {entry_data['name']}")
                    
                    # Start lazy loading for double-click navigation
                    self.lazy_loader = LazyDirectoryLoader(self.current_fs_info, path, self)
                    self.lazy_loader.directory_loaded.connect(
                        lambda loaded_path, entries: self.on_double_click_loaded(loaded_path, entries, path)
                    )
                    self.lazy_loader.error_occurred.connect(self.on_lazy_load_error)
                    self.lazy_loader.start()

    def on_double_click_loaded(self, loaded_path, entries, target_path):
        """Handle lazy loaded directory for double-click navigation"""
        if loaded_path == target_path:
            if loaded_path in self.loading_items:
                del self.loading_items[loaded_path]

            # Store in cache
            self.current_directory_data[loaded_path] = entries

            # Navigate to the directory
            self.populate_file_table(entries)
            self.update_path_display(loaded_path)
            
            # Update tree selection
            self.update_tree_selection(loaded_path)
            
            self.status_label.setText(f"✅ Navigated to: {os.path.basename(loaded_path)}")

    def update_tree_selection(self, path):
        """Update tree widget selection to match current path"""
        try:
            # Find and select the corresponding tree item
            def find_item_by_path(parent_item, target_path):
                if parent_item is None:
                    # Search from root
                    for i in range(self.tree_widget.topLevelItemCount()):
                        item = self.tree_widget.topLevelItem(i)
                        result = find_item_by_path(item, target_path)
                        if result:
                            return result
                else:
                    # Check current item
                    entry_data = parent_item.data(0, Qt.UserRole)
                    if entry_data and entry_data.get('path') == target_path:
                        return parent_item
                    
                    # Search children
                    for i in range(parent_item.childCount()):
                        child = parent_item.child(i)
                        result = find_item_by_path(child, target_path)
                        if result:
                            return result
                return None
            
            target_item = find_item_by_path(None, path)
            if target_item:
                self.tree_widget.setCurrentItem(target_item)
                # Expand parent items if necessary
                parent = target_item.parent()
                while parent:
                    parent.setExpanded(True)
                    parent = parent.parent()
                    
        except Exception as e:
            logger.debug(f"Could not update tree selection for path {path}: {e}")

    def show_tree_context_menu(self, position):
        """Show context menu for tree widget"""
        item = self.tree_widget.itemAt(position)
        if not item:
            return

        menu = QMenu(self)
        menu.addAction("📂 Expand All", lambda: item.expandAll())
        menu.addAction("📁 Collapse All", lambda: item.collapseAll())
        menu.addSeparator()
        menu.addAction("🔄 Refresh", lambda: self.refresh_tree_item(item))
        menu.exec_(self.tree_widget.mapToGlobal(position))

    def show_file_context_menu(self, position):
        """Show context menu for file table"""
        item = self.file_table.itemAt(position)
        if not item:
            return

        menu = QMenu(self)
        selected_items = self.file_table.selectedItems()
        if selected_items:
            menu.addAction("📤 Export Selected", self.export_selected_files)

        menu.addSeparator()
        menu.addAction("📦 Export All", self.export_all_files)
        menu.addSeparator()
        menu.addAction("🔄 Refresh", self.refresh_file_table)
        menu.exec_(self.file_table.mapToGlobal(position))

    def refresh_tree_item(self, item):
        """Refresh a specific tree item"""
        if not item:
            return

        entry_data = item.data(0, Qt.UserRole)
        if entry_data:
            path = entry_data['path']

            # Remove from cache to force reload
            if path in self.current_directory_data:
                del self.current_directory_data[path]

            # Remove from loading items
            if path in self.loading_items:
                del self.loading_items[path]

            # Clear children and add loading dummy only if has subdirectories
            item.takeChildren()
            if entry_data.get('has_children', False):
                dummy = QTreeWidgetItem(item)
                dummy.setText(0, "Loading...")

    def refresh_file_table(self):
        """Refresh the current file table view"""
        if self.current_path in self.current_directory_data:
            del self.current_directory_data[self.current_path]

        # Remove from loading items
        if self.current_path in self.loading_items:
            del self.loading_items[self.current_path]

        # Reload directory
        if self.current_fs_info:
            self.loading_items[self.current_path] = None
            self.lazy_loader = LazyDirectoryLoader(self.current_fs_info, self.current_path, self)
            self.lazy_loader.directory_loaded.connect(self.on_refresh_loaded)
            self.lazy_loader.error_occurred.connect(self.on_lazy_load_error)
            self.lazy_loader.start()

    def on_refresh_loaded(self, path, entries):
        """Handle refreshed directory contents"""
        if path in self.loading_items:
            del self.loading_items[path]

        # Store in cache
        self.current_directory_data[path] = entries

        # Update file table if this is the current path
        if path == self.current_path:
            self.populate_file_table(entries)

    def export_selected_files(self):
        """Export selected files with options dialog"""
        selected_rows = set()
        for item in self.file_table.selectedItems():
            selected_rows.add(item.row())

        if not selected_rows:
            QMessageBox.information(self, "Information", "Please select files to export.")
            return

        # Get selected file data
        items_to_export = []
        for row in selected_rows:
            item = self.file_table.item(row, 0)
            if item:
                entry_data = item.data(Qt.UserRole)
                if entry_data:
                    items_to_export.append(entry_data)

        if not items_to_export:
            return

        self._export_files_with_options(items_to_export, "Export Selected Files")

    def export_all_files(self):
        """Export all files in current directory with options dialog"""
        if self.current_path not in self.current_directory_data:
            QMessageBox.information(self, "Information", "No files to export.")
            return

        items_to_export = self.current_directory_data[self.current_path]
        if not items_to_export:
            QMessageBox.information(self, "Information", "No files to export.")
            return

        self._export_files_with_options(items_to_export, "Export All Files")

    def _export_files_with_options(self, items_to_export, title):
        """Export files with options dialog"""
        # Show export options dialog
        options_dialog = ExportOptionsDialog(self)
        if options_dialog.exec_() != QDialog.Accepted:
            return

        # Get export directory
        export_dir = QFileDialog.getExistingDirectory(
            self, title, "", QFileDialog.ShowDirsOnly
        )

        if not export_dir:
            return

        # Prepare export options
        export_options = {
            'generate_csv': options_dialog.generate_csv,
            'include_hashes': options_dialog.include_hashes,
            'hash_types': options_dialog.hash_types
        }

        # Start export worker
        if not self.current_fs_info:
            QMessageBox.warning(self, "Warning", "No filesystem loaded.")
            return

        self.export_worker = ForensicExportWorker(
            self.current_img_info,
            self.current_fs_info,
            items_to_export,
            export_dir,
            export_options
        )

        self.export_worker.progress_updated.connect(self.update_progress)
        self.export_worker.status_updated.connect(self.update_status)
        self.export_worker.export_completed.connect(self.export_finished)
        self.export_worker.error_occurred.connect(self.show_error)

        # Disable export buttons during export
        self.export_selected_btn.setEnabled(False)
        self.export_all_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        self.export_worker.start()

    def export_finished(self, success_count, total_count):
        """Handle export completion"""
        self.progress_bar.setVisible(False)
        self.export_selected_btn.setEnabled(True)
        self.export_all_btn.setEnabled(True)

        # Show completion message
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setWindowTitle("Export Complete")
        msg.setText(f"Export completed successfully!")
        msg.setDetailedText(f"Successfully exported {success_count} out of {total_count} items.")
        msg.setStyleSheet("QMessageBox { font-size: 12px; }")
        msg.exec_()

        self.status_label.setText(f"✅ Export completed: {success_count}/{total_count} items")


def main():
    """Main application entry point"""
    try:
        # Check for missing dependencies and warn user
        missing_deps = []
        if not PYVSHADOW_AVAILABLE:
            missing_deps.append("pyvshadow (Volume Shadow Copy detection will be disabled)")
        if not BITLOCKER_AVAILABLE:
            missing_deps.append("pybde (BitLocker support will be disabled)")
        if not PYWIN32_AVAILABLE:
            missing_deps.append("pywin32 (Advanced timestamp preservation will be limited)")
        if missing_deps:
            print("⚠️ Warning: Missing optional dependencies:")
            for dep in missing_deps:
                print(f" - {dep}")
            print(" The application will continue with reduced functionality.\n")

        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
        app = QApplication(sys.argv)
        app.setStyle(QStyleFactory.create('Fusion'))
        app.setApplicationName("VSC Explorer")
        app.setApplicationVersion("1.0")
        app.setOrganizationName("Forensic Tools")

        window = ForensicExplorerMainWindow()
        window.show()
        logger.info("VSC Explorer started successfully")
        sys.exit(app.exec_())

    except Exception as e:
        logger.critical(f"Failed to start application: {e}")
        print(f"Critical error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
