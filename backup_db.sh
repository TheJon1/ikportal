#!/bin/bash

DB_PATH="/home/ubuntu2026/ik/ik.db"
BACKUP_DIR="/home/ubuntu2026/ik_backup"
DATE=$(date +"%Y-%m-%d_%H-%M")

# Yedek al
sqlite3 "$DB_PATH" ".backup '$BACKUP_DIR/ik_$DATE.db'"

# 14 günden eski yedekleri sil
find "$BACKUP_DIR" -type f -name "*.db" -mtime +14 -delete
