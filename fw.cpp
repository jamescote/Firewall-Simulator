// file: fw.cpp
// Desc: ...
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

// Function Declarations

// Main
int main( int iArgC, char* pArgs[] )
{
	// Local Variables
	input_Handler* m_pInptHndlr;
	string sFileName;
	
	// Handle Arguments
	if ( MAX_ARG_COUNT > iArgC )
	{
		cout << "Configuration file required!\n";
		return 0;
	}

	// Load config file
	m_pInptHndlr = input_Handler::getInstance();
	m_pInptHndlr->loadRuleSet( pArgs[ 1 ] );

	// Process STDIO

	// Clean up

	//Exit
	return 1;
}
