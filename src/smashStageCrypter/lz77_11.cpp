#include "lz77_11.h"

LZ77_11::LZ77_11()
{
}

QByteArray LZ77_11::Compress( const QByteArray &stuff )
{
	// Test if the file is too large to be compressed
	if( (quint64)stuff.size() > 0xFFFFFFFF )
	{
		qDebug() << "LZ77_11::Compress -> Input file is too large to compress.";
		return QByteArray();
	}

	quint32 decompressedSize = stuff.size();

	quint32 SourcePointer = 0x0;
	quint32 DestPointer   = 0x4;

	quint32 tmp;
	QByteArray ret( decompressedSize, '\0' );//will reduce the size later
	QBuffer buf( &ret );
	buf.open( QIODevice::WriteOnly );


	// Set up the Lz Compression Dictionary
	LzWindowDictionary LzDictionary;
	LzDictionary.SetWindowSize( 0x1000 );
	LzDictionary.SetMaxMatchAmount( 0xFFFF + 273 );

	// Figure out where we are going to write the decompressed file size
	if( stuff.size() <= 0xFFFFFF )
	{
		tmp = ( decompressedSize << 8 ) | 0x11;									//dont switch endian?
		buf.write( (const char*)&tmp, 4 );
	}
	else
	{
		tmp = 0x11;
		buf.write( (const char*)&tmp, 4 );										//dont switch endian?
		tmp = decompressedSize;
		buf.write( (const char*)&tmp, 4 );										//dont switch endian?
		DestPointer += 0x4;
	}

	// Start compression
	while( SourcePointer < decompressedSize )
	{
		quint8 Flag = 0x0;
		quint32 FlagPosition = DestPointer;
		// It will be filled in later
		buf.putChar( Flag );
		DestPointer++;

		for( int i = 7; i >= 0; i-- )
		{
			QList<int>LzSearchMatch = LzDictionary.Search( stuff, SourcePointer, decompressedSize );
			if( LzSearchMatch[ 1 ] > 0 ) // There is a compression match
			{
				Flag |= (quint8)( 1 << i );

				// Write the distance/length pair
				if( LzSearchMatch[ 1 ] <= 0xF + 1 ) // 2 bytes
				{
					buf.putChar( (quint8)( (  ( ( LzSearchMatch[ 1 ] - 1) & 0xF ) << 4 ) | ( ( ( LzSearchMatch[ 0 ] - 1 ) & 0xFFF ) >> 8 ) ) );
					buf.putChar( (quint8)( ( LzSearchMatch[ 0 ] - 1 ) & 0xFF ) );
					DestPointer += 2;
				}
				else if (LzSearchMatch[1] <= 0xFF + 17) // 3 bytes
				{
					buf.putChar( (quint8)(((LzSearchMatch[1] - 17) & 0xFF) >> 4) );
					buf.putChar( (quint8)((((LzSearchMatch[1] - 17) & 0xF) << 4) | (((LzSearchMatch[0] - 1) & 0xFFF) >> 8)) );
					buf.putChar( (quint8)((LzSearchMatch[0] - 1) & 0xFF) );
					DestPointer += 3;
				}
				else // 4 bytes
				{
					buf.putChar( (quint8)((1 << 4) | (((LzSearchMatch[1] - 273) & 0xFFFF) >> 12)) );
					buf.putChar( (quint8)(((LzSearchMatch[1] - 273) & 0xFFF) >> 4) );
					buf.putChar( (quint8)((((LzSearchMatch[1] - 273) & 0xF) << 4) | (((LzSearchMatch[0] - 1) & 0xFFF) >> 8)) );
					buf.putChar( (quint8)((LzSearchMatch[0] - 1) & 0xFF) );
					DestPointer += 4;
				}

				LzDictionary.AddEntryRange( stuff, (int)SourcePointer, LzSearchMatch[ 1 ] );
				LzDictionary.SlideWindow( LzSearchMatch[ 1 ] );

				SourcePointer += (quint32)LzSearchMatch[ 1 ];
			}
			else // There wasn't a match
			{
				Flag |= (quint8)(0 << i);

				buf.putChar( stuff.at( SourcePointer ) );

				LzDictionary.AddEntry( stuff, (int)SourcePointer );
				LzDictionary.SlideWindow( 1 );

				SourcePointer++;
				DestPointer++;
			}

			// Check for out of bounds
			if( SourcePointer >= decompressedSize )
				break;
		}

		// Write the flag.
		// Note that the original position gets reset after writing.
		buf.seek( FlagPosition );
		buf.putChar( Flag );
		buf.seek( DestPointer );
	}

	buf.close();
	ret.resize( DestPointer );
	return ret;
}

LzWindowDictionary::LzWindowDictionary()
{
	WindowSize     = 0x1000;
	WindowStart    = 0;
	WindowLength   = 0;
	MinMatchAmount = 3;
	MaxMatchAmount = 18;
	BlockSize      = 0;
}

QList<int> LzWindowDictionary::Search( const QByteArray &DecompressedData, quint32 offset, quint32 length )
{
	RemoveOldEntries( DecompressedData[ offset ] ); // Remove old entries for this index

	if( offset < (quint32)MinMatchAmount || length - offset < (quint32)MinMatchAmount ) // Can't find matches if there isn't enough data
		return QList<int>() << 0 << 0;

	QList<int>Match = QList<int>() << 0 << 0;
	int MatchStart;
	int MatchSize;

	for( int i = OffsetList[ (quint8)( DecompressedData[ offset ] ) ].size() - 1; i >= 0; i-- )
	{
		MatchStart = OffsetList[ (quint8)( DecompressedData[ offset ] ) ][ i ];
		MatchSize  = 1;

		while( MatchSize < MaxMatchAmount
			   && MatchSize < WindowLength
			   && (quint32)(MatchStart + MatchSize) < offset
			   && offset + MatchSize < length
			   && DecompressedData[ offset + MatchSize ] == DecompressedData[ MatchStart + MatchSize ] )
			MatchSize++;

		if( MatchSize >= MinMatchAmount && MatchSize > Match[ 1 ] ) // This is a good match
		{
			Match = QList<int>() << (int)(offset - MatchStart) << MatchSize;

			if( MatchSize == MaxMatchAmount ) // Don't look for more matches
				break;
		}
	}

	// Return the match.
	// If no match was made, the distance & length pair will be zero
	return Match;
}

// Slide the window
void LzWindowDictionary::SlideWindow( int Amount )
{
	if( WindowLength == WindowSize )
		WindowStart += Amount;
	else
	{
		if( WindowLength + Amount <= WindowSize )
			WindowLength += Amount;
		else
		{
			Amount -= ( WindowSize - WindowLength );
			WindowLength = WindowSize;
			WindowStart += Amount;
		}
	}
}

// Slide the window to the next block
void LzWindowDictionary::SlideBlock()
{
	WindowStart += BlockSize;
}

// Remove old entries
void LzWindowDictionary::RemoveOldEntries( quint8 index )
{
	for( int i = 0; i < OffsetList[ index ].size(); ) // Don't increment i
	{
		if( OffsetList[ index ][ i ] >= WindowStart )
			break;
		else
			OffsetList[ index ].removeAt( 0 );
	}
}

// Set variables
void LzWindowDictionary::SetWindowSize( int size )
{
	WindowSize = size;
}
void LzWindowDictionary::SetMinMatchAmount( int amount )
{
	MinMatchAmount = amount;
}
void LzWindowDictionary::SetMaxMatchAmount( int amount )
{
	MaxMatchAmount = amount;
}
void LzWindowDictionary::SetBlockSize( int size )
{
	BlockSize    = size;
	WindowLength = size; // The window will work in blocks now
}

// Add entries
void LzWindowDictionary::AddEntry( const QByteArray &DecompressedData, int offset )
{
	OffsetList[ (quint8)( DecompressedData[ offset ] ) ] << offset;
}
void LzWindowDictionary::AddEntryRange( const QByteArray &DecompressedData, int offset, int length )
{
	for( int i = 0; i < length; i++ )
		AddEntry( DecompressedData, offset + i );
}
