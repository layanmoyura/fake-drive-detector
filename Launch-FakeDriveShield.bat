@echo off
title Fake Drive Detector & Reclaimer Shield v1.0
powershell -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File """%~dp0FakeDriveShield.ps1"""'"
