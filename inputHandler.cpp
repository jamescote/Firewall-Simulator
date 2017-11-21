// File: inputHandler.cpp
// Desc: Implementation of the input_Handler Class.
// Written by: James Cote
// ID: 10146559
// Tutorial: T01

// Includes
#include "inputHandler.h"
#include <fstream>
#include <limits>

// Define
#define BUFFER_SIZE 256
#define MIN_ARG_COUNT 4
#define COMMENT_FLAG '#'
#define ERROR_VAL -1
#define DIRECTION 0
#define ACTION 1
#define IP 2
#define PACKET_IP 1
#define PORTS 3
#define PACKET_PORT 2
#define PACKET_FLAG 3
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

// Purges input of any leading and trailing whitespace.
// Also replaces any \n \v \f \r or \t with a space instead for splitting the string.
void input_Handler::purgeWhitespace( string& sInput )
{
	// Local Variables
	size_t iFoundPos;
	string sWhitespaces( " \n\v\f\r\t" );

	// Clear any trailing whitespace
	while ( !sInput.empty() && (0 == sInput.back() || isspace( sInput.back() )) )
		sInput.pop_back();
	
	// exit if input is empty.
	if ( sInput.empty() )
		return;
	
	// Clear leading whitespace.
	iFoundPos = sInput.find_first_not_of( sWhitespaces );
	if( iFoundPos != string::npos )
		sInput = sInput.substr( iFoundPos );
	
	// Replace any unwanted whitespace characters with spaces.
	while ( string::npos != (iFoundPos = sInput.find_first_of( '\t' )) )
		sInput[ iFoundPos ] = ' ';
	while ( string::npos != (iFoundPos = sInput.find_first_of( '\f' )) )
		sInput[ iFoundPos ] = ' ';
	while ( string::npos != (iFoundPos = sInput.find_first_of( '\v' )) )
		sInput[ iFoundPos ] = ' ';
	while ( string::npos != (iFoundPos = sInput.find_first_of( '\r' )) )
		sInput[ iFoundPos ] = ' '; 
}

// Given a file name, open the file and build a ruleset from that file.
int input_Handler::loadRuleSet( string sFileName )
{
	// Local Variables
	ifstream pRuleFile( sFileName );
	int iReturnVal = 1, iLineCount = 1;
	string sCommandLine;
	char sBuffer[ BUFFER_SIZE ] = { 0 };

	// File opened?
	if ( pRuleFile.is_open() )
	{
		// Read until end of file
		while ( !pRuleFile.eof() )
		{
			// Read new line.
			pRuleFile.getline( sBuffer, BUFFER_SIZE - 1 );
			sCommandLine.assign( sBuffer, pRuleFile.gcount() );

			// Check input
			if ( (pRuleFile.fail() ^ pRuleFile.bad()) && pRuleFile.gcount() > 0 )	// Line too long
			{
				// Output warning then read rest of the line.
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

		// Close the file afterwards
		pRuleFile.close();
	}
	else	// Failed to open file.
	{
		iReturnVal = ERROR_VAL;
		cout << "Error\n";
	}

	// Return result.
	return iReturnVal;
}

// Compares incoming packet against established ruleset. Returns a standard result to be output by caller.
void input_Handler::handlePacket( string sInput, string& sOutput )
{
	// Local Variables
	vector< string > sPacketParts;
	vector< stRule >::iterator Rule_Iter;
	stRule sPacket;
	bool bValidInput = false;

	// Split Input
	splitString( sInput, ' ', sPacketParts );

	if ( sPacketParts.size() == MIN_ARG_COUNT )
	{
		// Handle Packet - Generate a Packet as a Firewall Rule for comparison
		bValidInput = handleDirection( sPacketParts[ DIRECTION ], sPacket.m_bIncoming );
		bValidInput = bValidInput && breakdownIP( sPacketParts[ PACKET_IP ], sPacket.m_iIP, sPacket.m_iIPMask, sPacket.m_bAnyIP );
		bValidInput = bValidInput && breakdownPorts( sPacketParts[ PACKET_PORT ], sPacket.m_shPorts );
		if ( !sPacketParts[ PACKET_FLAG ].compare( "1" ) )
			sPacket.m_bEstablished = true;
		else if ( !sPacketParts[ PACKET_FLAG ].compare( "0" ) )
			sPacket.m_bEstablished = false;

		// Won't accept a null IP or no port specified.
		bValidInput = bValidInput && !sPacket.m_shPorts.empty() && sPacket.m_iIP;

		// Match packet with rule
		if ( bValidInput )
		{
			// Find rule
			for ( Rule_Iter = m_stRuleSet.begin();
				  Rule_Iter != m_stRuleSet.end();
				  ++Rule_Iter )
			{
				if ( Rule_Iter->isMatch( sPacket ) )
					break; // Found rule
			}

			// Default is Drop
			if ( Rule_Iter == m_stRuleSet.end() )
			{
				sOutput.assign( sActionStrings[ DROP_ACT ] );
				sOutput += "() ";
			}
			else	// Otherwise, append action and rule number.
			{
				sOutput.assign( sActionStrings[ Rule_Iter->m_eAction ] );
				sOutput += "(" + to_string( Rule_Iter->m_iRuleNumber ) + ") ";
			}

			// Finally, Append on the packet that this rule applies to.
			sOutput += sInput;
		}
	}
	
	// Default input error handling
	if ( !bValidInput )
		sOutput = "Bad Packet input: " + sInput;
}

/************************************************************************************\
* RuleSet Input Handlers															*
\************************************************************************************/
// Handles line of input from ruleset. Deals with bad input and generates a rule from good input.
int input_Handler::handleRuleSetLine( string& sLine, int iLineNum )
{
	// Local Variables
	int iReturnValue = 1;
	size_t st_CommentLoc = sLine.find_first_of( COMMENT_FLAG );
	vector< string > sBreakdown;
	stRule sNewRule;

	// Clean any comments from the line.
	if ( string::npos != st_CommentLoc )
		sLine.erase( st_CommentLoc );

	// Split line into individual parts
	splitString( sLine, ' ', sBreakdown );

	// Not enough parameters => erroneous input.
	if ( sBreakdown.size() < MIN_ARG_COUNT )
		iReturnValue = ERROR_VAL;
	else
	{	
		// Parse each piece of the rule individually to generate rule.
		iReturnValue = iReturnValue && handleDirection( sBreakdown[ DIRECTION ], sNewRule.m_bIncoming );
		iReturnValue = iReturnValue && handleAction( sBreakdown[ ACTION ], sNewRule.m_eAction );
		iReturnValue = iReturnValue && breakdownIP( sBreakdown[ IP ], sNewRule.m_iIP, sNewRule.m_iIPMask, sNewRule.m_bAnyIP );
		iReturnValue = iReturnValue && breakdownPorts( sBreakdown[ PORTS ], sNewRule.m_shPorts );
		if ( sBreakdown.size() > FLAG )
			sNewRule.m_bEstablished = !sBreakdown[ FLAG ].compare( sEstablishedValue );
		else
			sNewRule.m_bEstablished = false;

		// If ruleset was generated without issue => store rule.
		if ( SUCCESS == iReturnValue )
		{
			sNewRule.m_iRuleNumber = iLineNum;
			m_stRuleSet.push_back( sNewRule );
		}
	}
	// Report result.
	return iReturnValue;
}

// Breaksdown the IP into an unsigned int for the IP itself and an unsigned int for the mask that specifies the important bits of the IP
//		As per CIDR specifications.
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
			sIPSplit.pop_back();
			splitString( sIP, '/', sIPSplit );

			// Create IP Address Value
			for ( int i = 0; i < IP_BYTES; ++i )
			{
				try
				{
					iRetIP = iRetIP << BYTE_LENGTH;
					iIPByte = stoi( sIPSplit[ i ] );
					iRetIP |= iIPByte;
				}
				catch ( const exception& e )
				{ return 0; }
			}

			// Set Bit Mask
			if ( sIPSplit.size() == (IP_BYTES + 1) )	// If a bit mask was specified.
			{
				try
				{	// Shift IP Mask that has all bits set over by the inverse of the CIDR value (32 - x)
					iRetIPMask = iRetIPMask << (NUM_BITS_IN_INT - stoi( sIPSplit[ IP_BYTES ] ));
				}
				catch ( const exception& e )
				{ return 0; }
			}
		}
	}
	
	// Return result
	return iReturnVal;
}

// Handles ruleset input for ports. Each port is split by a single comma, so seperate string by comma then evaluate each
//		resulting string as a possible port entry.
int input_Handler::breakdownPorts( string sPorts, vector< unsigned short >& vshRetPorts )
{
	// Local Variables
	vector< string > sPortsList;
	unsigned int iNewPort;

	// * = any port valid
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

// converts a string into its corresponding eAction enum. 
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

	// Return Result.
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

	// Return result
	return iReturnVal;
}
