#ifndef INPUT_HANDLER
#define INPUT_HANDLER

// Includes
#include <string>
#include <cstdlib>
#include <vector>
#include <iostream>
#include <sstream>
#include <iterator>

// Namespaces
using namespace std;

// Class: input_Handler
// Desc: Stores connection information such as Nonce, IV, Secret and Session Key and commands.
//			Handles encryption and decryption, socket IO, HMAC generation and message handling between server and client.
// Written by: James Cote
// ID: 10146559
// Tutorial: T01
class input_Handler
{
public: // Singleton implementation.
	static input_Handler* getInstance();
	~input_Handler();

	// Message Handling
	int loadRuleSet( string sFileName );
	void handlePacket( string sInput, string& sOutput );

private:
	// Singleton Implementation
	static input_Handler* m_pInstance;
	input_Handler();
	input_Handler& operator= ( const input_Handler& pCopy ) { return *this; }
	input_Handler( const input_Handler& pCopy ) {}

	enum eAction
	{
		DROP_ACT = 0,
		ACCEPT_ACT,
		REJECT_ACT,
		MAX_ACTIONS
	};

	// RuleSet Input Handlers
	int breakdownIP( string sIP, unsigned int& iRetIP, unsigned int& iRetIPMask, bool& bRetAnyIP );
	int breakdownPorts( string sPorts, vector< unsigned short >& vshRetPorts );
	int handleAction( string sAction, eAction& eRetAction );
	int handleDirection( string sDirection, bool& bRetDirection );
	void splitString( string& sInput, char delim, vector<string>& sOutput );
	void purgeWhitespace( string& sInput );
	int handleRuleSetLine( string& sLine, int iLineCount );

	struct stRule
	{
		int m_iRuleNumber;
		bool m_bIncoming;
		eAction m_eAction;
		unsigned int m_iIP;
		bool m_bAnyIP;
		unsigned int m_iIPMask;
		vector< unsigned short > m_shPorts;
		bool m_bEstablished;

		// Format Rule into string for debug.
		string toString()
		{
			string sReturn = "Line: ";
			string sIPAddress = "*";
			unsigned int iWorkingIP = m_iIP;
			unsigned char iMaskCount = 0;
			sReturn += to_string( m_iRuleNumber );
			sReturn += " ";
			sReturn += (m_bIncoming ? "in " : "out ");

			if ( !m_bAnyIP )
			{
				sIPAddress.clear();

				for ( int i = 24; i >= 0; i -= 8 )
				{
					iWorkingIP = m_iIP >> i;
					sIPAddress += to_string( iWorkingIP & 255 ) + ".";
				}
				sIPAddress.pop_back();
				sIPAddress.push_back( '/' );

				iWorkingIP = m_iIPMask;
				while ( iWorkingIP )
				{
					iMaskCount += iWorkingIP & 1;
					iWorkingIP = iWorkingIP >> 1;
				}
				sIPAddress += to_string( iMaskCount );
			}
			sReturn += sIPAddress + " ";

			if ( m_shPorts.empty() )
				sReturn += "* ";
			else
			{
				for ( vector< unsigned short >::iterator iter = m_shPorts.begin();
				iter != m_shPorts.end();
				++iter )
					sReturn += to_string( (*iter) ) + ",";

				sReturn.pop_back();
			}

			sReturn += (m_bEstablished ? " 1" : " 0");

			return sReturn;
		}
	};
	vector< stRule > m_stRuleSet;
};

#endif
