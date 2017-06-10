/*
 * StopException.h
 *
 *  Created on: Nov 9, 2016
 *      Author: jefgrailet
 *
 * Exception thrown when WIP Traceroute has entered the stop mode. Identical to what can be found 
 * in TreeNET.
 */

#ifndef STOPEXCEPTION_H_
#define STOPEXCEPTION_H_

#include <stdexcept>
using std::runtime_error;
#include <string>
using std::string;

class StopException : public runtime_error
{
public:
	StopException(const string &msg="WIP Traceroute is stopping");
	virtual ~StopException() throw();
};

#endif /* STOPEXCEPTION_H_ */
