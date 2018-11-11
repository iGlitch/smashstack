#-------------------------------------------------
#
# Project created by QtCreator 2011-01-31T20:13:12
#
#-------------------------------------------------

QT       += core

QT       -= gui

TARGET = smashStageCrypter
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app


SOURCES += main.cpp \
    Crypter.c \
    AES/AEStab.c \
    AES/AESkey.c \
    AES/AEScrypt.c \
    AES/AES.c \
    lz77_11.cpp

HEADERS += \
    Crypter.h \
    AES/AESopt.h \
    AES/AES.h \
    lz77_11.h
