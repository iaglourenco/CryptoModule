#!/bin/sh

dmesg -w -k -H -T | grep -i crypto
