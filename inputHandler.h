#ifndef INPUT_HANDLER
#define INPUT_HANDLER

// Includes
#include <string>
#include <cstdlib>
#include <vector>
#include <iostream>
#include <sstream>
#include <iterator>
#include <algorithm>

// Namespaces
using namespace std;

// Class: input_Handler
// Desc: Handles ruleset construction and management. Handles incoming packets and evaluates them against established ruleset.
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
		// Member variables
		int m_iRuleNumber;
		bool m_bIncoming;
		eAction m_eAction;
		unsigned int m_iIP;
		bool m_bAnyIP;
		unsigned int m_iIPMask;
		vector< unsigned short > m_shPorts;
		bool m_bEstablished;

		// Checks if an incoming packet matches this rule.
		bool isMatch( const stRule& stPacket )
		{
			bool bResult = stPacket.m_bIncoming == this->m_bIncoming;	// Check if rule handles incoming or outgoing.
			bResult = bResult && (!this->m_iIP || ((this->m_iIP & this->m_iIPMask) == (stPacket.m_iIP & this->m_iIPMask)));	// Check IP
			bResult = bResult && (!this->m_bEstablished || stPacket.m_bEstablished);	// Check if packet needs to have been established or not.
			bResult = bResult &&	// Check that incoming packet is on a port used by this rule.
						(this->m_shPorts.empty() || 
						(find( this->m_shPorts.begin(), this->m_shPorts.end(), stPacket.m_shPorts[ 0 ] ) != this->m_shPorts.end()));
			return bResult;
		}
	};
	vector< stRule > m_stRuleSet;
};

#endif
