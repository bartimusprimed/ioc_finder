import pywin32_system32
import win32evtlog
import win32evtlogutil
import win32security
import win32con
import winerror
import time
import re
import string
import sys
import traceback
import os
import difflib

class Logger:

	def __init__(self):
		self.computer = os.environ['COMPUTERNAME']
		self.log_holder = {"System": [], "Security": [], "Application": [], "Microsoft-Windows-AppModel-Runtime/Admin": []}
		self.log = {'System': [], 'Security': [], 'Application': [], 'Microsoft-Windows-AppModel-Runtime/Admin': []}
		self.choices = {
			'Successful Pass the Hash': {'event id': [4672], 'logs': ['Security'], 'level': None}, #this is a test item clear it.
			'Failed Pass the Hash': {'event id': [], 'logs': [], 'level': None},
			'Log Clear Check': {'event id': [1102, 104], 'logs': ['Security', 'System'], 'level': 4},
			'Firewall Rules': {'event id': [], 'logs': [], 'level': None},
			'Service Add': {'event id': [7045], 'logs': ['System'], 'level': None},
			'Application Errors': {'event id': [1000], 'logs': ['Application'], 'level': 2 },
			'Application Hangs': {'event id': [1002], 'logs': ['Application'], 'level': 2 },
			'BSOD': {'event id': [1001], 'logs': ['System'], 'level': 2},
			'Windows Error Reporting': {'event id': [1001], 'logs': ['Application'], 'level': 4},
			'Service Fails': {'event id': [7022,7023,7024,7026,7031,7032,7034], 'logs': ['System'], 'level': 2},
			'EMET': {'event id': [1,2], 'logs': ['Application'], 'provider name': 'EMET', 'level': None},
			'Kernel Filter Drivers': {'event id': [6], 'logs': ['System'], 'level': None},
			'MSI Installs': {'event id': [1022,1033], 'logs': ['Application'], 'provider name': 'MsiInstaller', 'level': 4},
			'Account Lockout Checks': {'event id': [4740], 'logs': ['Security'], 'level': 4},
			'User Priviledges Checks': {'event id': [4728,4732,4756], 'logs': ['Security'], 'level': None},
			'Security Enabled Group Modification': {'event id': [4735], 'logs': ['Security'], 'level': None},
			'Failed User Account Logins': {'event id': [4625], 'logs': ['Security'], 'level': None},
			'Invalid Image Hash (Kernel)': {'event id': [5038], 'logs': ['Security'], 'level': None},
			'Invalid Page Hash (Kernel)': {'event id': [6281], 'logs': ['Security'], 'level': None},
			'Code Integrity Check (Kernel)': {'event id': [3001,3002,3003,3004,3010,3023], 'logs': [], 'provider name': 'Microsoft-Windows-CodeIntegrity', 'level': None},
			'Failed Kernel Driver Check': {'event id': [219], 'logs': ['System'], 'level': None},
			'Password Changes': {'event id': [4610,4611,4614,4622], 'logs': ['Security'], 'level': 0},
			'Mass Storage': {'event id': [400,410], 'logs': [], 'provider name': 'Microsoft-Windows-Kernel-PnP', 'level': None},
			'Scheduled Tasks': {'event id': [4698,4699,4700,4701,4702], 'logs': ['Security'], 'level': None},
			'Registry Key Checks': {'event id': [4657], 'logs': ['Security'], 'level': None},
			'Kernel-EventTracing': {'event id': [916], 'logs': ['Microsoft-Windows-AppModel-Runtime/Admin'], 'level': None}
		}

	def getLogs(self):
		for log in self.log_holder.keys():
			hand = win32evtlog.OpenEventLog(self.computer, log)
			numRecords = win32evtlog.GetNumberOfEventLogRecords(hand)
			flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
			while 1:
				events = win32evtlog.ReadEventLog(hand,flags,0)
				if not events:
					break
				for event in events:
					self.log_holder[log].append(event)

	def readLogs(self, log):
		for ev_obj in self.log_holder[log]:
			temp_dict = {}
			try:
				temp_dict['Source'] = str(ev_obj.SourceName).strip()
			except:
				pass
			try:
				temp_dict['Time'] = ev_obj.TimeGenerated.Format()
			except:
				pass
			try:
				temp_dict['Event ID'] = str(winerror.HRESULT_CODE(ev_obj.EventID)).strip()
			except:
				pass
			try:
				temp_dict['Computer Name'] = str(ev_obj.ComputerName).strip()
			except:
				pass
			try:
				temp_dict['Category'] = str(ev_obj.EventCategory).strip()
			except:
				pass
			try:
				temp_dict['Record Number'] = str(ev_obj.RecordNumber).strip()
			except:
				pass
			try:
				temp_dict['Message'] = str(win32evtlogutil.SafeFormatMessage(ev_obj, log)).strip()
			except:
				pass
			try:
				temp_dict['Provider Name'] = str(ev_obj.Provider).strip()
			except:
				pass
			try:
				temp_dict['Level'] = str(ev_obj.Level).strip()
			except:
				pass
			self.log[log].append(temp_dict)

	def showPossible(self, event="Pass the Hash"):
		event = self.parse_event(event)
		if len(event) > 1:
			event = input("Which one would you like? {} \n".format(event))
			event = self.parse_event(event)
		if event:
			print("Looking for possible '{}'".format(event[0]))
			self.find_event(event[0])
		else:
			print("Nothing was found. List of choices: {}")
	
	def parse_event(self, event):
		list_of_choices = [x.lower() for x in self.choices.keys()]
		if event in list_of_choices:
			return [event]
		return difflib.get_close_matches(event.lower(), list_of_choices, n=5, cutoff=0.3)

	def find_event(self, event):
		try:
			key = difflib.get_close_matches(event, [x for x in self.choices.keys()], n=1, cutoff=0.7)[0]
		except:
			key = difflib.get_close_matches(event, [x for x in self.choices.keys()], n=1, cutoff=0.2)[0]
		try:
			count = 0
			result = False
			if self.choices[key]['logs']:
				for x in self.choices[key]['logs']:
					for event in self.log[x]:
						try:
							for x in self.choices[key]['event id']:
								if int(x) == int(event['Event ID']):
									count += 1
									print("\n------\nFound an event: {}\n-------\n".format(event['Message']))
									result = True
						except:
							result = False
						
			if not result:
				print("No log found")
		except Exception as e:
			print("Could not find event {}".format(e))
		print("Total events found: {}".format(count))

win_log = Logger()
win_log.getLogs()
win_log.readLogs("Application")
win_log.readLogs("System")
win_log.readLogs("Security")
win_log.readLogs("Microsoft-Windows-AppModel-Runtime/Admin")
event = input("What type of event would you like to find? ")
win_log.showPossible(event)
