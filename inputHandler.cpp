// File: inputHandler.cpp
// Desc: Implementation of the input_Handler Class.
// Written by: James Cote
// ID: 10146559
// Tutorial: T01

// Includes
#include "inputHandler.h"
#include <fstream>
#include <limits>

/**
#define DEBUG
//*/
// Define
#define BUFFER_SIZE 256
#define MIN_ARG_COUNT 4
#define COMMENT_FLAG '#'
#define ERROR_VAL -1
#define DIRECTION 0
#define ACTION 1
#define IP 2
#define PORTS 3
#define FLAG 4
#define SUCCESS 1
#define FAIL 0
#define IP_BYTES 4
#define BYTE_LENGTH 8
#define NUM_BITS_IN_INT 32

// Constants
const char* sEstablishedValue	= { "established" };
const char* IN					= { "in" };
const char* OUT					= { "out" };

// Message Strings
const char* sActionStrings[] = { "drop",
								 "accept",
								 "reject" };

// Singleton Implementation
input_Handler* input_Handler::m_pInstance = NULL;

// Returns the singleton instance of input_Handler
input_Handler* input_Handler::getInstance()
{
	if ( NULL == m_pInstance )
		m_pInstance = new input_Handler();
	return m_pInstance;
}

// Default Constructor
input_Handler::input_Handler()
{
	// Nothing to Construct.
}

// Destructor -> lose reference to Server
input_Handler::~input_Handler()
{
	// Nothing to Destruct
}

/************************************************************************************\
 * Message Handling																	*
\************************************************************************************/

// Splits a String up into a vector of strings by a character deliminator "delim"
// Vector of strings returned in sOutput
void input_Handler::splitString( string& sInput, char delim, vector<string>& sOutput )
{
	// Local Variables
	stringstream sStrStream;
	string sElement;

	purgeWhitespace( sInput );
	sStrStream.str( sInput );	// Use String Stream to parse the string

	// Get a line and push the new string back into the vector.
	while ( getline( sStrStream, sElement, delim ) )
		if ( sElement[ 0 ] != '\0' )
			sOutput.push_back( sElement );
}

void input_Handler::purgeWhitespace( string& sInput )
{
	// Local Variables
	size_t iFoundPos, iLastPos;

	if ( sInput.empty() )
		return;

	while ( string::npos != (iFoundPos = sInput.find_first_of( '\t' )) )
		sInput[ iFoundPos ] = ' ';
	while ( string::npos != (iFoundPos = sInput.find_first_of( '\f' )) )
		sInput[ iFoundPos ] = ' ';
	while ( string::npos != (iFoundPos = sInput.find_first_of( '\v' )) )
		sInput[ iFoundPos ] = ' ';
	while ( string::npos != (iFoundPos = sInput.find_first_of( '\r' )) )
		sInput[ iFoundPos ] = ' '; 

	// Clear leading and trailing whitespace.
	iFoundPos = sInput.find_first_not_of( ' ' );
	iLastPos = sInput.find_last_not_of( ' ' );

	cout << "iFoundPos = " << iFoundPos << "; iLastPos = " << iLastPos << endl;
	sInput = sInput.substr( iFoundPos, iLastPos - iFoundPos - 1 );
}

int input_Handler::loadRuleSet( string sFileName )
{
	// Local Variables
	ifstream pRuleFile( sFileName );
	int iReturnVal, iLineCount = 1;
	string sCommandLine;
	char sBuffer[ BUFFER_SIZE ] = { 0 };
	vector< string > sTestingStrings;

	if ( pRuleFile.is_open() )
	{
		while ( !pRuleFile.eof() )
		{
			pRuleFile.getline( sBuffer, BUFFER_SIZE - 1 );
			sCommandLine.assign( sBuffer, pRuleFile.gcount() );

			// Check input
			if ( (pRuleFile.fail() ^ pRuleFile.bad()) && pRuleFile.gcount() > 0 )	// Line too long
			{
				cout << "Warning: Buffer Overflow: (line  " << iLineCount << "): \"" << sCommandLine;
				while ( pRuleFile.fail() )
				{
					pRuleFile.clear();
					pRuleFile.getline( sBuffer, BUFFER_SIZE - 1 );
					cout << sBuffer;
				}
				cout << "\"\n";
			}
			else if ( pRuleFile.bad() )	// Error in IO
				cout << "Error on file stream: gcount: " << pRuleFile.gcount() << "; input: " << sCommandLine << endl;
			else if ( !handleRuleSetLine( sCommandLine, iLineCount ) )	// Unable to Handle Rule
				cout << "Warning: Bad input: (line " << iLineCount << "): \"" << sCommandLine << "\"\n";

			// Increment Line Count.
			++iLineCount;
		}
	}
	else
	{
		iReturnVal = ERROR_VAL;
		cout << "Error\n";
	}

	for ( vector< stRule >::iterator iter = m_stRuleSet.begin();
		 iter != m_stRuleSet.end();
		 ++iter )
		cout << iter->toString() << endl;

	pRuleFile.close();

	return iReturnVal;//*/

	return 1;
}

void input_Handler::handlePacket( string sInput, string& sOutput )
{

}

/************************************************************************************\
* RuleSet Input Handlers															*
\************************************************************************************/
int input_Handler::handleRuleSetLine( string& sLine, int iLineNum )
{
	// Local Variables
	int iReturnValue = 1;
	vector< string > sBreakdown;
	stRule sNewRule;

	splitString( sLine, ' ', sBreakdown );

	if ( sBreakdown.size() < MIN_ARG_COUNT )
		iReturnValue = ERROR_VAL;
	else
	{
	#ifdef DEBUG
		cout << "Entered handleRuleSetLine; split: [";
		for ( vector< string >::iterator iter = sBreakdown.begin();
			  iter != sBreakdown.end();
			  ++iter )
			cout << (*iter) << (iter + 1 == sBreakdown.end() ? "]\n" : "|");
	#endif // DEBUG
		if ( COMMENT_FLAG != sBreakdown[ 0 ][ 0 ] )
		{
			iReturnValue = iReturnValue && handleDirection( sBreakdown[ DIRECTION ], sNewRule.m_bIncoming );
		#ifdef DEBUG
			cout << "Finished handleDirection: input: \"" << sBreakdown[ DIRECTION ] << "\" sNewRule.m_bIncoming: <"
				<< (sNewRule.m_bIncoming ? "in" : "out") << "> returned: " << (iReturnValue ? "<1>" : "<0>") << endl;
		#endif
			iReturnValue = iReturnValue && handleAction( sBreakdown[ ACTION ], sNewRule.m_eAction );
		#ifdef DEBUG
			cout << "Finished handleAction: input: \"" << sBreakdown[ ACTION ] << "\" sNewRule.m_eAction: <"
				<< (sNewRule.m_eAction == MAX_ACTIONS ? "NULL" : sActionStrings[ sNewRule.m_eAction ] ) << "> returned: " << (iReturnValue ? "<1>" : "<0>") << endl;
		#endif
			iReturnValue = iReturnValue && breakdownIP( sBreakdown[ IP ], sNewRule.m_iIP, sNewRule.m_iIPMask, sNewRule.m_bAnyIP );
		#ifdef DEBUG
			cout << "Finished breakdownIP: input: \"" << sBreakdown[ IP ] << "\" sNewRule.m_iIP: <"
				<< sNewRule.m_iIP << "> sNewRule.m_iIPMask: <" << sNewRule.m_iIPMask << "> sNewRule.m_bAnyIP: <" << (sNewRule.m_bAnyIP ? "true" : "false") << "> returned: " << (iReturnValue ? "<1>" : "<0>") << endl;
		#endif
			iReturnValue = iReturnValue && breakdownPorts( sBreakdown[ PORTS ], sNewRule.m_shPorts );
		#ifdef DEBUG
			cout << "Finished breakdownPorts: input: \"" << sBreakdown[ PORTS ] << "\" sNewRule.m_shPorts: <";
			for ( vector< unsigned short >::iterator iter = sNewRule.m_shPorts.begin();
				 iter != sNewRule.m_shPorts.end();
				 ++iter )
				cout << (*iter) << (iter + 1 == sNewRule.m_shPorts.end() ? "" : ",");
			cout << "> returned: " << (iReturnValue ? "<1>" : "<0>") << endl;

			cout << "Breakdown Size: " << sBreakdown.size() << " vs. Flag: " << FLAG << "\n";
		#endif
			if ( sBreakdown.size() > FLAG )
			{
				sNewRule.m_bEstablished = !sBreakdown[ FLAG ].compare( sEstablishedValue );
			#ifdef DEBUG
				cout << "\tRead: " << (sNewRule.m_bEstablished ? "established" : sBreakdown[ FLAG ]) << endl;
			#endif
			}

			if ( SUCCESS == iReturnValue )
			{
				sNewRule.m_iRuleNumber = iLineNum;
				m_stRuleSet.push_back( sNewRule );
			}
		}
	}
	return iReturnValue;
}

int input_Handler::breakdownIP( string sIP, unsigned int& iRetIP, unsigned int& iRetIPMask, bool& bRetAnyIP )
{
	// Local Variables
	int iReturnVal = 1;
	vector< string > sIPSplit;
	vector< string > sCIDRLast;
	int iIPByte = 0;

	// Generate Default Values.
	iRetIP = 0;
	iRetIPMask = -1;
	bRetAnyIP = true;

	// Skip if any IP acceptable
	if ( sIP.compare( "*" ) )
	{
		bRetAnyIP = false;

		// Split by '.'
		splitString( sIP, '.', sIPSplit );

		// Check Size.
		if ( sIPSplit.size() != IP_BYTES )
			iReturnVal = 0;
		else
		{
			// Check for CIDR ending.
			sIP.assign( sIPSplit.back() );
			splitString( sIP, '/', sIPSplit );

			// Create IP Address Value
			for ( int i = 0; i < IP_BYTES; ++i )
			{
				try
				{
					iIPByte = stoi( sIPSplit[ i ] );
					iRetIP |= iIPByte;
					iRetIP = iRetIP << BYTE_LENGTH;
				}
				catch ( const exception& e )
				{ return 0; }
			}

			// Set Bit Mask
			if ( sIPSplit.size() == (IP_BYTES + 1) )
			{
				try
				{
					iRetIPMask = iRetIPMask << (NUM_BITS_IN_INT - stoi( sIPSplit[ IP_BYTES + 1 ] ));
				}
				catch ( const exception& e )
				{ return 0; }
			}

		}
			
	}
	
	return iReturnVal;
}

int input_Handler::breakdownPorts( string sPorts, vector< unsigned short >& vshRetPorts )
{
	// Local Variables
	vector< string > sPortsList;
	unsigned int iNewPort;

	if ( sPorts.compare( "*" ) )
	{
		// Split ports by comma
		splitString( sPorts, ',', sPortsList );

		// Process each port individually.
		for ( unsigned int i = 0; i < sPortsList.size(); ++i )
		{
			try
			{ // Try to read in a short.
				iNewPort = stoi( sPortsList[ i ] );
				if ( iNewPort >= 0 && iNewPort < numeric_limits< unsigned short >::max() )
					vshRetPorts.push_back( (unsigned short) iNewPort );
				else
					return 0;	// Out of Range for Short
			} 
			catch ( const exception& e )
			{ return 0;	}// Bad input.
		}
	}

	// Return success. 
	return 1;
}

int input_Handler::handleAction( string sAction, eAction& eRetAction )
{
	// Local Variables
	int iReturnVal = 1;

	// Set a default value
	eRetAction = MAX_ACTIONS;

	// Compare with all possible actions.
	for( int i = 0; i < MAX_ACTIONS; ++i )
		if ( !sAction.compare( sActionStrings[ i ] ) )
		{
			eRetAction = (eAction) i;
			break;
		}

	// Was a valid action entered?
	if ( MAX_ACTIONS == eRetAction )
		iReturnVal = 0;

	// Return Result.*/
	return iReturnVal;
}

// Handles input for the Direction parameter from the configuration file.
int input_Handler::handleDirection( string sDirection, bool& bRetDirection )
{
	// Local Variables
	int iReturnVal = 1;

	// Does it equal "in"?
	bRetDirection = !sDirection.compare( IN );
	
	// If it did not equal "in" and it doesn't equal "out" => bad input.
	if ( !bRetDirection && sDirection.compare( OUT ) )
		iReturnVal = 0;

	// Return result */
	return iReturnVal;
}
