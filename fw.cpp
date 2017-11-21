// file: fw.cpp
// Desc: Implements main entry logic for the Firewall simulator.
//			Takes in 1 argument that is used to load a rule set then reads incoming packets from standard input and outputs the
//			handled result of each packet.
// Written by: James Cote
// ID: 10146559
// Tutorial: T01

// Includes
#include "inputHandler.h"

// Defines
#define COMMAND 1
#define FILE_NAME 2
#define IP_PORT 3
#define CIPHER 4
#define SECRET_KEY 5
#define MAX_ARG_COUNT 2
#define IP_PORT_COUNT 2
#define PACKET_SIZE 256

// Main
int main( int iArgC, char* pArgs[] )
{
	// Local Variables
	input_Handler* m_pInptHndlr;
	int iLoadResult;
	char sBuffer[ PACKET_SIZE ] = { 0 };
	string sPacket, sPacketResult;
	
	// Handle Arguments
	if ( MAX_ARG_COUNT > iArgC )
	{
		cout << "Configuration file required!\n";
		return 0;
	}

	// Load config file
	m_pInptHndlr = input_Handler::getInstance();
	iLoadResult = m_pInptHndlr->loadRuleSet( pArgs[ 1 ] );

	// Process STDIO
	if ( 0 < iLoadResult )
	{
		while ( !cin.eof() )
		{
			// Get Next Line
			cin.getline( sBuffer, PACKET_SIZE - 1 );
			sPacket.assign( sBuffer, cin.gcount() );

			if ( !sPacket.empty() )	// Only handle valid input.
			{
				sPacketResult.clear();
				m_pInptHndlr->handlePacket( sPacket, sPacketResult );

				cout << sPacketResult << endl;
			}
		}
	}

	// Clean up
	delete m_pInptHndlr;

	//Exit
	return 1;
}
