package main

const (
	PROFILE_WEB uint = 0x25
	PROFILE_SMB uint = 0x15
	PROFILE_DOH uint = 0x40
	PROFILE_DNS uint = 0x30
	PROFILE_TCP uint = 0x10
)

const (
	MSG_QUICK byte = 0x5
	MSG_OUT   byte = 0x7
)

const (
	TASK_GET    byte = 0
	TASK_RESULT byte = 1
)