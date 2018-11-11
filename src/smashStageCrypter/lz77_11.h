#ifndef LZ77_11_H
#define LZ77_11_H

#include <QtCore/QCoreApplication>
#include <QFile>
#include <QDebug>

#include <QtGui/QApplication>
#include <QBuffer>
#include <QDir>
#include <QList>
#include <qendian.h>
#include <QRegExp>

class LZ77_11
{
public:
    LZ77_11();
	static QByteArray Compress( const QByteArray &stuff );
};

class LzWindowDictionary
{
public:
	LzWindowDictionary();

	QList<int> Search( const QByteArray &DecompressedData, quint32 offset, quint32 length );
	void SlideWindow( int Amount );
	void SlideBlock();
	void RemoveOldEntries( quint8 index );
	void SetWindowSize( int size );
	void SetMinMatchAmount( int amount );
	void SetMaxMatchAmount( int amount );
	void SetBlockSize( int size );
	void AddEntry( const QByteArray &DecompressedData, int offset );
	void AddEntryRange( const QByteArray &DecompressedData, int offset, int length );

private:
	int WindowSize;
	int WindowStart;
	int WindowLength;
	int MinMatchAmount;
	int MaxMatchAmount;
	int BlockSize;
	QList<int> OffsetList[ 0x100 ];
};

#endif // LZ77_11_H
