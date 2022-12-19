#!/bin/bash
sudo pkill xrdp
sudo pkill xrdp-sesman
sudo pkill xrdp-chansrv
sudo pkill Xorg
sudo systemctl restart xrdp
sudo systemctl restart xrdp-sesman