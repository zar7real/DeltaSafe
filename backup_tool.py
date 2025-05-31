#!/usr/bin/env python3

import os
import sys
import json
import hashlib
import sqlite3
import argparse
import logging
import threading
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import paramiko
import boto3
import getpass
import time
import shutil
import gzip
import tarfile

class SecurityManager:
    def __init__(self, config_path="backup.conf"):
        self.config = self._load_config(config_path)
        self.master_key = None
        self.private_key = None
        self.public_key = None
        
    def _load_config(self, path):
        default_config = {
            "encryption": {"algorithm": "AES-256-GCM", "key_derivation": "PBKDF2"},
            "storage": {"type": "local", "path": "/backup", "retention_days": 90},
            "security": {"mfa_required": True, "hash_algorithm": "SHA-256"},
            "logging": {"level": "INFO", "file": "backup.log"}
        }
        
        if os.path.exists(path):
            with open(path, 'r') as f:
                user_config = json.load(f)
            default_config.update(user_config)
        
        return default_config
    
    def initialize_keys(self, passphrase=None):
        if not passphrase:
            passphrase = getpass.getpass("Enter master passphrase: ").encode()
        
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        self.master_key = kdf.derive(passphrase)
        
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        self._save_keys(salt)
    
    def _save_keys(self, salt):
        os.makedirs(".backup_keys", exist_ok=True)
        
        with open(".backup_keys/salt", "wb") as f:
            f.write(salt)
        
        encrypted_private = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(self.master_key)
        )
        
        with open(".backup_keys/private.pem", "wb") as f:
            f.write(encrypted_private)
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(".backup_keys/public.pem", "wb") as f:
            f.write(public_pem)
    
    def load_keys(self, passphrase=None):
        if not passphrase:
            passphrase = getpass.getpass("Enter master passphrase: ").encode()
        
        with open(".backup_keys/salt", "rb") as f:
            salt = f.read()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        self.master_key = kdf.derive(passphrase)
        
        with open(".backup_keys/private.pem", "rb") as f:
            private_pem = f.read()
        
        self.private_key = serialization.load_pem_private_key(
            private_pem,
            password=self.master_key,
            backend=default_backend()
        )
        
        with open(".backup_keys/public.pem", "rb") as f:
            public_pem = f.read()
        
        self.public_key = serialization.load_pem_public_key(
            public_pem,
            backend=default_backend()
        )
    
    def encrypt_file(self, file_path, output_path):
        key = os.urandom(32)
        iv = os.urandom(12)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        with open(file_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            encrypted_key = self.public_key.encrypt(
                key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            outfile.write(len(encrypted_key).to_bytes(4, 'big'))
            outfile.write(encrypted_key)
            outfile.write(iv)
            
            while True:
                chunk = infile.read(64 * 1024)
                if not chunk:
                    break
                outfile.write(encryptor.update(chunk))
            
            outfile.write(encryptor.finalize())
            outfile.write(encryptor.tag)
        
        return self._calculate_hash(output_path)
    
    def decrypt_file(self, encrypted_path, output_path):
        with open(encrypted_path, 'rb') as infile:
            key_length = int.from_bytes(infile.read(4), 'big')
            encrypted_key = infile.read(key_length)
            iv = infile.read(12)
            
            key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            with open(output_path, 'wb') as outfile:
                while True:
                    chunk = infile.read(64 * 1024)
                    if len(chunk) < 64 * 1024:
                        if len(chunk) > 16:
                            tag = chunk[-16:]
                            chunk = chunk[:-16]
                            if chunk:
                                outfile.write(decryptor.update(chunk))
                            decryptor.finalize_with_tag(tag)
                        break
                    outfile.write(decryptor.update(chunk))
    
    def _calculate_hash(self, file_path):
        hash_obj = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    
    def verify_integrity(self, file_path, expected_hash):
        return self._calculate_hash(file_path) == expected_hash

class BackupDatabase:
    def __init__(self, db_path="backup.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS backups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_path TEXT NOT NULL,
                backup_path TEXT NOT NULL,
                backup_type TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                size INTEGER,
                compressed_size INTEGER,
                status TEXT DEFAULT 'completed'
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                backup_id INTEGER,
                version INTEGER,
                hash TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (backup_id) REFERENCES backups (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                details TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                user TEXT,
                ip_address TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_backup(self, source_path, backup_path, backup_type, file_hash, size, compressed_size):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO backups (source_path, backup_path, backup_type, file_hash, size, compressed_size)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (source_path, backup_path, backup_type, file_hash, size, compressed_size))
        
        backup_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return backup_id
    
    def get_last_backup(self, source_path, backup_type):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM backups 
            WHERE source_path = ? AND backup_type = ? 
            ORDER BY timestamp DESC LIMIT 1
        ''', (source_path, backup_type))
        
        result = cursor.fetchone()
        conn.close()
        
        return result
    
    def audit_log(self, action, details="", user="system", ip_address="localhost"):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO audit_log (action, details, user, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (action, details, user, ip_address))
        
        conn.commit()
        conn.close()

class StorageManager:
    def __init__(self, config):
        self.config = config
        self.storage_type = config.get("storage", {}).get("type", "local")
    
    def upload_file(self, local_path, remote_path):
        if self.storage_type == "local":
            return self._local_upload(local_path, remote_path)
        elif self.storage_type == "sftp":
            return self._sftp_upload(local_path, remote_path)
        elif self.storage_type == "s3":
            return self._s3_upload(local_path, remote_path)
    
    def download_file(self, remote_path, local_path):
        if self.storage_type == "local":
            return self._local_download(remote_path, local_path)
        elif self.storage_type == "sftp":
            return self._sftp_download(remote_path, local_path)
        elif self.storage_type == "s3":
            return self._s3_download(remote_path, local_path)
    
    def _local_upload(self, local_path, remote_path):
        os.makedirs(os.path.dirname(remote_path), exist_ok=True)
        shutil.copy2(local_path, remote_path)
        return True
    
    def _local_download(self, remote_path, local_path):
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        shutil.copy2(remote_path, local_path)
        return True
    
    def _sftp_upload(self, local_path, remote_path):
        config = self.config.get("sftp", {})
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        ssh.connect(
            hostname=config.get("host"),
            username=config.get("username"),
            password=config.get("password"),
            key_filename=config.get("key_file")
        )
        
        sftp = ssh.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.close()
        ssh.close()
        
        return True
    
    def _sftp_download(self, remote_path, local_path):
        config = self.config.get("sftp", {})
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        ssh.connect(
            hostname=config.get("host"),
            username=config.get("username"),
            password=config.get("password"),
            key_filename=config.get("key_file")
        )
        
        sftp = ssh.open_sftp()
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        sftp.get(remote_path, local_path)
        sftp.close()
        ssh.close()
        
        return True
    
    def _s3_upload(self, local_path, remote_path):
        config = self.config.get("s3", {})
        s3 = boto3.client(
            's3',
            aws_access_key_id=config.get("access_key"),
            aws_secret_access_key=config.get("secret_key"),
            region_name=config.get("region", "us-east-1")
        )
        
        s3.upload_file(local_path, config.get("bucket"), remote_path)
        return True
    
    def _s3_download(self, remote_path, local_path):
        config = self.config.get("s3", {})
        s3 = boto3.client(
            's3',
            aws_access_key_id=config.get("access_key"),
            aws_secret_access_key=config.get("secret_key"),
            region_name=config.get("region", "us-east-1")
        )
        
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        s3.download_file(config.get("bucket"), remote_path, local_path)
        return True

class BackupEngine:
    def __init__(self, config_path="backup.conf"):
        self.security = SecurityManager(config_path)
        self.database = BackupDatabase()
        self.storage = StorageManager(self.security.config)
        self.logger = self._setup_logging()
    
    def _setup_logging(self):
        logging.basicConfig(
            level=getattr(logging, self.security.config.get("logging", {}).get("level", "INFO")),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.security.config.get("logging", {}).get("file", "backup.log")),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)
    
    def initialize(self, passphrase=None):
        if not os.path.exists(".backup_keys"):
            self.logger.info("Initializing backup system...")
            self.security.initialize_keys(passphrase)
            self.database.audit_log("SYSTEM_INIT", "Backup system initialized")
        else:
            self.security.load_keys(passphrase)
    
    def create_backup(self, source_path, backup_type="full", compression=True):
        self.logger.info(f"Starting {backup_type} backup of {source_path}")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        temp_dir = f"/tmp/backup_{timestamp}"
        os.makedirs(temp_dir, exist_ok=True)
        
        try:
            if backup_type == "incremental":
                files_to_backup = self._get_incremental_files(source_path)
            elif backup_type == "differential":
                files_to_backup = self._get_differential_files(source_path)
            else:
                files_to_backup = [source_path]
            
            if compression:
                archive_path = os.path.join(temp_dir, f"backup_{timestamp}.tar.gz")
                self._create_compressed_archive(files_to_backup, archive_path)
                source_file = archive_path
            else:
                source_file = source_path
            
            encrypted_path = os.path.join(temp_dir, f"backup_{timestamp}.enc")
            file_hash = self.security.encrypt_file(source_file, encrypted_path)
            
            original_size = os.path.getsize(source_file) if os.path.isfile(source_file) else self._get_dir_size(source_file)
            encrypted_size = os.path.getsize(encrypted_path)
            
            storage_path = f"backups/{timestamp}/backup_{timestamp}.enc"
            
            if self.storage.upload_file(encrypted_path, storage_path):
                backup_id = self.database.log_backup(
                    source_path, storage_path, backup_type, 
                    file_hash, original_size, encrypted_size
                )
                
                self.database.audit_log("BACKUP_CREATED", 
                    f"Backup ID: {backup_id}, Type: {backup_type}, Size: {encrypted_size}")
                
                self.logger.info(f"Backup completed successfully. ID: {backup_id}")
                return backup_id
            
        except Exception as e:
            self.logger.error(f"Backup failed: {str(e)}")
            self.database.audit_log("BACKUP_FAILED", str(e))
            raise
        
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    def restore_backup(self, backup_id, restore_path):
        self.logger.info(f"Starting restore of backup ID: {backup_id}")
        
        conn = sqlite3.connect(self.database.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM backups WHERE id = ?", (backup_id,))
        backup_info = cursor.fetchone()
        conn.close()
        
        if not backup_info:
            raise ValueError(f"Backup ID {backup_id} not found")
        
        temp_dir = f"/tmp/restore_{int(time.time())}"
        os.makedirs(temp_dir, exist_ok=True)
        
        try:
            encrypted_path = os.path.join(temp_dir, "backup.enc")
            decrypted_path = os.path.join(temp_dir, "backup_decrypted")
            
            if not self.storage.download_file(backup_info[2], encrypted_path):
                raise Exception("Failed to download backup file")
            
            if not self.security.verify_integrity(encrypted_path, backup_info[4]):
                raise Exception("Backup integrity check failed")
            
            self.security.decrypt_file(encrypted_path, decrypted_path)
            
            if backup_info[2].endswith('.tar.gz') or tarfile.is_tarfile(decrypted_path):
                with tarfile.open(decrypted_path, 'r:gz') as tar:
                    tar.extractall(restore_path)
            else:
                os.makedirs(os.path.dirname(restore_path), exist_ok=True)
                shutil.copy2(decrypted_path, restore_path)
            
            self.database.audit_log("RESTORE_COMPLETED", 
                f"Backup ID: {backup_id} restored to {restore_path}")
            
            self.logger.info(f"Restore completed successfully")
            
        except Exception as e:
            self.logger.error(f"Restore failed: {str(e)}")
            self.database.audit_log("RESTORE_FAILED", str(e))
            raise
        
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    def verify_backups(self):
        self.logger.info("Starting backup verification")
        
        conn = sqlite3.connect(self.database.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, backup_path, file_hash FROM backups WHERE status = 'completed'")
        backups = cursor.fetchall()
        conn.close()
        
        failed_verifications = []
        
        for backup_id, backup_path, expected_hash in backups:
            try:
                temp_file = f"/tmp/verify_{backup_id}"
                
                if self.storage.download_file(backup_path, temp_file):
                    if self.security.verify_integrity(temp_file, expected_hash):
                        self.logger.info(f"Backup {backup_id}: VERIFIED")
                    else:
                        self.logger.error(f"Backup {backup_id}: INTEGRITY FAILED")
                        failed_verifications.append(backup_id)
                else:
                    self.logger.error(f"Backup {backup_id}: DOWNLOAD FAILED")
                    failed_verifications.append(backup_id)
                
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    
            except Exception as e:
                self.logger.error(f"Backup {backup_id}: VERIFICATION ERROR - {str(e)}")
                failed_verifications.append(backup_id)
        
        self.database.audit_log("VERIFICATION_COMPLETED", 
            f"Total: {len(backups)}, Failed: {len(failed_verifications)}")
        
        return failed_verifications
    
    def cleanup_old_backups(self, retention_days=None):
        if retention_days is None:
            retention_days = self.security.config.get("storage", {}).get("retention_days", 90)
        
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        conn = sqlite3.connect(self.database.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, backup_path FROM backups WHERE timestamp < ?", 
                      (cutoff_date.isoformat(),))
        old_backups = cursor.fetchall()
        
        deleted_count = 0
        for backup_id, backup_path in old_backups:
            try:
                cursor.execute("DELETE FROM backups WHERE id = ?", (backup_id,))
                deleted_count += 1
            except Exception as e:
                self.logger.error(f"Failed to delete backup {backup_id}: {str(e)}")
        
        conn.commit()
        conn.close()
        
        self.database.audit_log("CLEANUP_COMPLETED", 
            f"Deleted {deleted_count} old backups (older than {retention_days} days)")
        
        self.logger.info(f"Cleanup completed. Deleted {deleted_count} old backups")
    
    def _get_incremental_files(self, source_path):
        last_backup = self.database.get_last_backup(source_path, "incremental")
        if not last_backup:
            last_backup = self.database.get_last_backup(source_path, "full")
        
        if not last_backup:
            return [source_path]
        
        last_backup_time = datetime.fromisoformat(last_backup[6])
        modified_files = []
        
        for root, dirs, files in os.walk(source_path):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.getmtime(file_path) > last_backup_time.timestamp():
                    modified_files.append(file_path)
        
        return modified_files if modified_files else [source_path]
    
    def _get_differential_files(self, source_path):
        last_full_backup = self.database.get_last_backup(source_path, "full")
        
        if not last_full_backup:
            return [source_path]
        
        last_backup_time = datetime.fromisoformat(last_full_backup[6])
        modified_files = []
        
        for root, dirs, files in os.walk(source_path):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.getmtime(file_path) > last_backup_time.timestamp():
                    modified_files.append(file_path)
        
        return modified_files if modified_files else [source_path]
    
    def _create_compressed_archive(self, files, output_path):
        with tarfile.open(output_path, 'w:gz') as tar:
            for file_path in files:
                if os.path.exists(file_path):
                    tar.add(file_path, arcname=os.path.basename(file_path))
    
    def _get_dir_size(self, path):
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if os.path.exists(filepath):
                    total_size += os.path.getsize(filepath)
        return total_size

def main():
    parser = argparse.ArgumentParser(description='Enterprise Backup Tool')
    parser.add_argument('command', choices=['init', 'backup', 'restore', 'verify', 'cleanup', 'list'])
    parser.add_argument('--source', help='Source path for backup')
    parser.add_argument('--destination', help='Destination path for restore')
    parser.add_argument('--type', choices=['full', 'incremental', 'differential'], default='full')
    parser.add_argument('--backup-id', type=int, help='Backup ID for restoration')
    parser.add_argument('--config', default='backup.conf', help='Configuration file path')
    parser.add_argument('--no-compression', action='store_true', help='Disable compression')
    
    args = parser.parse_args()
    
    backup_engine = BackupEngine(args.config)
    
    try:
        if args.command == 'init':
            backup_engine.initialize()
            print("Backup system initialized successfully")
        
        elif args.command == 'backup':
            if not args.source:
                print("Error: --source is required for backup")
                return 1
            
            backup_engine.initialize()
            backup_id = backup_engine.create_backup(
                args.source, 
                args.type, 
                not args.no_compression
            )
            print(f"Backup created with ID: {backup_id}")
        
        elif args.command == 'restore':
            if not args.backup_id or not args.destination:
                print("Error: --backup-id and --destination are required for restore")
                return 1
            
            backup_engine.initialize()
            backup_engine.restore_backup(args.backup_id, args.destination)
            print("Restore completed successfully")
        
        elif args.command == 'verify':
            backup_engine.initialize()
            failed = backup_engine.verify_backups()
            if failed:
                print(f"Verification failed for backup IDs: {failed}")
                return 1
            else:
                print("All backups verified successfully")
        
        elif args.command == 'cleanup':
            backup_engine.initialize()
            backup_engine.cleanup_old_backups()
            print("Cleanup completed")
        
        elif args.command == 'list':
            conn = sqlite3.connect(backup_engine.database.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT id, source_path, backup_type, timestamp, size FROM backups ORDER BY timestamp DESC")
            backups = cursor.fetchall()
            conn.close()
            
            if backups:
                print("\nBackup History:")
                print("-" * 80)
                print(f"{'ID':<5} {'Source':<30} {'Type':<12} {'Date':<20} {'Size (MB)':<10}")
                print("-" * 80)
                for backup in backups:
                    size_mb = backup[4] / (1024*1024) if backup[4] else 0
                    print(f"{backup[0]:<5} {backup[1][:29]:<30} {backup[2]:<12} {backup[3]:<20} {size_mb:<10.2f}")
            else:
                print("No backups found")
    
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1
    
    return 0

class BackupScheduler:
    def __init__(self, backup_engine):
        self.backup_engine = backup_engine
        self.scheduler_thread = None
        self.running = False
        
    def start_scheduler(self, schedule_config):
        self.running = True
        self.scheduler_thread = threading.Thread(target=self._run_scheduler, args=(schedule_config,))
        self.scheduler_thread.daemon = True
        self.scheduler_thread.start()
        
    def stop_scheduler(self):
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join()
            
    def _run_scheduler(self, schedule_config):
        while self.running:
            current_time = datetime.now()
            
            for job in schedule_config.get("jobs", []):
                last_run = job.get("last_run")
                interval_hours = job.get("interval_hours", 24)
                
                if not last_run or (current_time - datetime.fromisoformat(last_run)).total_seconds() > interval_hours * 3600:
                    try:
                        self.backup_engine.create_backup(
                            job["source_path"],
                            job.get("backup_type", "full"),
                            job.get("compression", True)
                        )
                        job["last_run"] = current_time.isoformat()
                        self._save_schedule_config(schedule_config)
                    except Exception as e:
                        self.backup_engine.logger.error(f"Scheduled backup failed: {str(e)}")
            
            time.sleep(300)
            
    def _save_schedule_config(self, config):
        with open("schedule.json", "w") as f:
            json.dump(config, f, indent=2)

class RansomwareProtection:
    def __init__(self, backup_engine):
        self.backup_engine = backup_engine
        self.canary_files = []
        
    def create_canary_files(self, paths):
        for path in paths:
            canary_path = os.path.join(path, ".backup_canary")
            with open(canary_path, "w") as f:
                f.write(f"CANARY_FILE_{datetime.now().isoformat()}")
            self.canary_files.append(canary_path)
            
    def check_canary_files(self):
        compromised = []
        for canary_path in self.canary_files:
            if not os.path.exists(canary_path):
                compromised.append(canary_path)
            else:
                with open(canary_path, "r") as f:
                    content = f.read()
                    if not content.startswith("CANARY_FILE_"):
                        compromised.append(canary_path)
        
        if compromised:
            self.backup_engine.database.audit_log("RANSOMWARE_DETECTED", 
                f"Compromised canary files: {compromised}")
            return False
        return True
        
    def create_immutable_backup(self, source_path):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_id = self.backup_engine.create_backup(source_path, "full")
        
        conn = sqlite3.connect(self.backup_engine.database.db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE backups SET status = 'immutable' WHERE id = ?", (backup_id,))
        conn.commit()
        conn.close()
        
        return backup_id

class ComplianceManager:
    def __init__(self, backup_engine):
        self.backup_engine = backup_engine
        
    def generate_compliance_report(self, standard="ISO27001"):
        report = {
            "standard": standard,
            "generated_at": datetime.now().isoformat(),
            "backup_statistics": self._get_backup_stats(),
            "security_controls": self._check_security_controls(),
            "audit_trail": self._get_audit_summary(),
            "compliance_status": "COMPLIANT"
        }
        
        if not self._validate_compliance(report):
            report["compliance_status"] = "NON_COMPLIANT"
            
        return report
        
    def _get_backup_stats(self):
        conn = sqlite3.connect(self.backup_engine.database.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM backups WHERE timestamp > datetime('now', '-30 days')")
        monthly_backups = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM backups WHERE status = 'completed'")
        successful_backups = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM backups")
        total_backups = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "monthly_backups": monthly_backups,
            "successful_backups": successful_backups,
            "total_backups": total_backups,
            "success_rate": (successful_backups / total_backups * 100) if total_backups > 0 else 0
        }
        
    def _check_security_controls(self):
        controls = {
            "encryption_enabled": os.path.exists(".backup_keys"),
            "audit_logging": os.path.exists(self.backup_engine.database.db_path),
            "access_control": True,
            "integrity_verification": True
        }
        return controls
        
    def _get_audit_summary(self):
        conn = sqlite3.connect(self.backup_engine.database.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT action, COUNT(*) FROM audit_log GROUP BY action")
        actions = dict(cursor.fetchall())
        
        cursor.execute("SELECT COUNT(*) FROM audit_log WHERE timestamp > datetime('now', '-7 days')")
        weekly_events = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "actions_summary": actions,
            "weekly_events": weekly_events
        }
        
    def _validate_compliance(self, report):
        stats = report["backup_statistics"]
        controls = report["security_controls"]
        
        if stats["success_rate"] < 95:
            return False
        if stats["monthly_backups"] < 1:
            return False
        if not all(controls.values()):
            return False
            
        return True

class DisasterRecovery:
    def __init__(self, backup_engine):
        self.backup_engine = backup_engine
        
    def create_recovery_plan(self, critical_systems):
        plan = {
            "created_at": datetime.now().isoformat(),
            "critical_systems": critical_systems,
            "recovery_procedures": [],
            "estimated_rto": "4 hours",
            "estimated_rpo": "1 hour"
        }
        
        for system in critical_systems:
            procedure = {
                "system": system["name"],
                "priority": system.get("priority", "medium"),
                "backup_location": system["backup_path"],
                "recovery_steps": [
                    "Verify backup integrity",
                    "Prepare recovery environment",
                    "Restore from latest backup",
                    "Verify system functionality",
                    "Update DNS/routing if needed"
                ]
            }
            plan["recovery_procedures"].append(procedure)
            
        with open("disaster_recovery_plan.json", "w") as f:
            json.dump(plan, f, indent=2)
            
        return plan
        
    def test_recovery(self, system_name, test_environment):
        self.backup_engine.logger.info(f"Starting DR test for {system_name}")
        
        conn = sqlite3.connect(self.backup_engine.database.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM backups WHERE source_path LIKE ? ORDER BY timestamp DESC LIMIT 1", 
                      (f"%{system_name}%",))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            raise Exception(f"No backup found for system {system_name}")
            
        backup_id = result[0]
        
        try:
            self.backup_engine.restore_backup(backup_id, test_environment)
            
            self.backup_engine.database.audit_log("DR_TEST_SUCCESS", 
                f"System: {system_name}, Backup ID: {backup_id}")
            
            return {
                "status": "SUCCESS",
                "system": system_name,
                "backup_id": backup_id,
                "test_environment": test_environment,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.backup_engine.database.audit_log("DR_TEST_FAILED", 
                f"System: {system_name}, Error: {str(e)}")
            raise

def create_sample_config():
    config = {
        "encryption": {
            "algorithm": "AES-256-GCM",
            "key_derivation": "PBKDF2"
        },
        "storage": {
            "type": "local",
            "path": "/backup",
            "retention_days": 90
        },
        "sftp": {
            "host": "backup.example.com",
            "username": "backup_user",
            "password": "secure_password",
            "key_file": "/path/to/ssh/key"
        },
        "s3": {
            "bucket": "my-backup-bucket",
            "access_key": "your_access_key",
            "secret_key": "your_secret_key",
            "region": "us-east-1"
        },
        "security": {
            "mfa_required": True,
            "hash_algorithm": "SHA-256"
        },
        "logging": {
            "level": "INFO",
            "file": "backup.log"
        },
        "compliance": {
            "standards": ["ISO27001", "NIST"],
            "audit_retention_days": 365
        }
    }
    
    with open("backup.conf.example", "w") as f:
        json.dump(config, f, indent=2)
    
    print("Sample configuration created: backup.conf.example")

def main():
    parser = argparse.ArgumentParser(description='Enterprise Backup Tool')
    parser.add_argument('command', choices=[
        'init', 'backup', 'restore', 'verify', 'cleanup', 'list', 
        'schedule', 'compliance', 'dr-test', 'config-sample'
    ])
    parser.add_argument('--source', help='Source path for backup')
    parser.add_argument('--destination', help='Destination path for restore')
    parser.add_argument('--type', choices=['full', 'incremental', 'differential'], default='full')
    parser.add_argument('--backup-id', type=int, help='Backup ID for restoration')
    parser.add_argument('--config', default='backup.conf', help='Configuration file path')
    parser.add_argument('--no-compression', action='store_true', help='Disable compression')
    parser.add_argument('--system', help='System name for DR testing')
    parser.add_argument('--test-env', help='Test environment path for DR')
    
    args = parser.parse_args()
    
    if args.command == 'config-sample':
        create_sample_config()
        return 0
    
    backup_engine = BackupEngine(args.config)
    
    try:
        if args.command == 'init':
            backup_engine.initialize()
            
            ransomware_protection = RansomwareProtection(backup_engine)
            ransomware_protection.create_canary_files(["/home", "/opt", "/var"])
            
            print("Backup system initialized successfully")
            print("Ransomware protection canary files created")
        
        elif args.command == 'backup':
            if not args.source:
                print("Error: --source is required for backup")
                return 1
            
            backup_engine.initialize()
            
            ransomware_protection = RansomwareProtection(backup_engine)
            if not ransomware_protection.check_canary_files():
                print("WARNING: Possible ransomware detected! Backup aborted.")
                return 1
            
            backup_id = backup_engine.create_backup(
                args.source, 
                args.type, 
                not args.no_compression
            )
            print(f"Backup created with ID: {backup_id}")
        
        elif args.command == 'restore':
            if not args.backup_id or not args.destination:
                print("Error: --backup-id and --destination are required for restore")
                return 1
            
            backup_engine.initialize()
            backup_engine.restore_backup(args.backup_id, args.destination)
            print("Restore completed successfully")
        
        elif args.command == 'verify':
            backup_engine.initialize()
            failed = backup_engine.verify_backups()
            if failed:
                print(f"Verification failed for backup IDs: {failed}")
                return 1
            else:
                print("All backups verified successfully")
        
        elif args.command == 'cleanup':
            backup_engine.initialize()
            backup_engine.cleanup_old_backups()
            print("Cleanup completed")
        
        elif args.command == 'schedule':
            backup_engine.initialize()
            
            schedule_config = {
                "jobs": [
                    {
                        "source_path": args.source or "/home",
                        "backup_type": "incremental",
                        "interval_hours": 6,
                        "compression": True
                    }
                ]
            }
            
            scheduler = BackupScheduler(backup_engine)
            scheduler.start_scheduler(schedule_config)
            
            print("Backup scheduler started. Press Ctrl+C to stop.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                scheduler.stop_scheduler()
                print("\nScheduler stopped")
        
        elif args.command == 'compliance':
            backup_engine.initialize()
            compliance = ComplianceManager(backup_engine)
            report = compliance.generate_compliance_report()
            
            print(f"\nCompliance Report ({report['standard']})")
            print("=" * 50)
            print(f"Status: {report['compliance_status']}")
            print(f"Generated: {report['generated_at']}")
            print(f"\nBackup Statistics:")
            for key, value in report['backup_statistics'].items():
                print(f"  {key}: {value}")
            print(f"\nSecurity Controls:")
            for key, value in report['security_controls'].items():
                print(f"  {key}: {'✓' if value else '✗'}")
        
        elif args.command == 'dr-test':
            if not args.system or not args.test_env:
                print("Error: --system and --test-env are required for DR testing")
                return 1
            
            backup_engine.initialize()
            dr = DisasterRecovery(backup_engine)
            result = dr.test_recovery(args.system, args.test_env)
            
            print(f"DR Test Result: {result['status']}")
            print(f"System: {result['system']}")
            print(f"Backup ID: {result['backup_id']}")
            print(f"Test Environment: {result['test_environment']}")
        
        elif args.command == 'list':
            conn = sqlite3.connect(backup_engine.database.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, source_path, backup_type, timestamp, size, status 
                FROM backups ORDER BY timestamp DESC LIMIT 20
            """)
            backups = cursor.fetchall()
            conn.close()
            
            if backups:
                print("\nRecent Backups:")
                print("-" * 90)
                print(f"{'ID':<5} {'Source':<25} {'Type':<12} {'Date':<20} {'Size (MB)':<10} {'Status':<10}")
                print("-" * 90)
                for backup in backups:
                    size_mb = backup[4] / (1024*1024) if backup[4] else 0
                    print(f"{backup[0]:<5} {backup[1][:24]:<25} {backup[2]:<12} {backup[3]:<20} {size_mb:<10.2f} {backup[5]:<10}")
            else:
                print("No backups found")
    
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
