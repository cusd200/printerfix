/*
 *
 * Printer Fix for CUSD 200
 * Copyright 2019 Daniel Sage
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// Include the SDK-defined version constants
#include <sdkddkver.h>

// Clear the Windows API version
#undef NTDDI_VERSION
#undef _WIN32_WINNT

// Enable all Windows 7 and later APIs
#define NTDDI_VERSION NTDDI_WIN7
#define _WIN32_WINNT  _WIN32_WINNT_WIN7
#define WINVER        _WIN32_WINNT

// Include the Windows API headers
#include <Windows.h>

#define PF_TITLE "Printer Fix for CUSD 200"

DWORD EnableShutdownPrivileges();

int CALLBACK WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
	// Question: Are you ready to restart your computer?
	auto response = ::MessageBox(HWND_DESKTOP, "Are you ready to restart your computer? This program will force your computer to restart immediately after changing a few settings.", PF_TITLE, MB_ICONQUESTION | MB_YESNO);

	// Check if the user chose _No_
	if (response == IDNO)
	{
		// Error: This program must restart your computer to work correctly. Please run the program when you are ready to restart!
		::MessageBox(HWND_DESKTOP, "This program must restart your computer to work correctly. Please run the program when you are ready to restart!", PF_TITLE, MB_ICONERROR);
		return -1;
	}

	// Define the key we are going to be re-creating
	auto key = "Printers\\Connections";

	// Delete all printer connections currently in the registry
	auto result = ::RegDeleteTree(HKEY_CURRENT_USER, key);

	// Check if the deletion failed
	if (result != ERROR_SUCCESS)
	{
		// Error: We could not delete the current printers!
		::MessageBox(HWND_DESKTOP, "We could not delete the current printers!", PF_TITLE, MB_ICONERROR);
		return result;
	}

	// Create a variable to hold the key we're about to create
	HKEY ignored;

	// Create the key again so Windows does not have a fit
	result = ::RegCreateKey(HKEY_CURRENT_USER, key, &ignored);

	// Verify that the key was created once again
	if (result != ERROR_SUCCESS)
	{
		// Error: We could not recreate the key we deleted!
		::MessageBox(HWND_DESKTOP, "We could not recreate the key we deleted!", PF_TITLE, MB_ICONERROR);
		return result;
	}

	// Create a variable to hold our DWORD value
	DWORD value = 1;

	// Enable DNS in the spooler service
	result = ::RegSetKeyValue(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Print", "DnsOnWire", REG_DWORD, (const BYTE*) &value, sizeof(value));

	// Verify that the key was created once again
	if (result != ERROR_SUCCESS)
	{
		// Error: We could not enable DNS in the spooler!
		::MessageBox(HWND_DESKTOP, "We could not enable DNS in the spooler!", PF_TITLE, MB_ICONERROR);
		return result;
	}

	// Disable strict name checking
	result = ::RegSetKeyValue(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "DisableStrictNameChecking", REG_DWORD, (const BYTE*) &value, sizeof(value));

	// Verify that the key was created once again
	if (result != ERROR_SUCCESS)
	{
		// Error: We could not disable strict name checking!
		::MessageBox(HWND_DESKTOP, "We could not disable strict name checking!", PF_TITLE, MB_ICONERROR);
		return result;
	}

	// TODO: Enable the shutdown privilege for this process
	result = EnableShutdownPrivileges();

	// Verify that shutdown privileges were added
	if (result != ERROR_SUCCESS)
	{
		// Error: We could not enable shutdown privileges!
		::MessageBox(HWND_DESKTOP, "We could not enable shutdown privileges!", PF_TITLE, MB_ICONERROR);
		return result;
	}

	// Reboot the system!
	::ExitWindowsEx(EWX_REBOOT, NULL);

	// Return
	return ERROR_SUCCESS;
}

DWORD EnableShutdownPrivileges()
{
	HANDLE token;

	// Get the access token for the current process
	if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_READ | TOKEN_ADJUST_PRIVILEGES, &token) == 0)
	{
		// Error: We could not get the access token!
		::MessageBox(HWND_DESKTOP, "We could not get the access token!", PF_TITLE, MB_ICONERROR);
		return ::GetLastError();
	}

	// Create the structure to hold the (very short) list of privileges
	TOKEN_PRIVILEGES privileges;
	LUID luid;

	// Lookup the value of the shutdown privilege
	if (::LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &luid) == 0)
	{
		// Close the token handle to prevent memory waste
		::CloseHandle(token);

		// Report the failure
		return ::GetLastError();
	}

	// Set the number of privileges to one
	privileges.PrivilegeCount = 1;

	// Add the privilege and request it be enabled
	privileges.Privileges[0].Luid = luid;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Adjust the privileges on the process token
	if (::AdjustTokenPrivileges(token, false, &privileges, NULL, NULL, NULL) == 0)
	{
		// Close the token handle to prevent memory waste
		::CloseHandle(token);

		// Report the failure
		return ::GetLastError();
	}

	// Close the token handle to prevent memory waste
	::CloseHandle(token);

	// In this rare case, assume success
	return ERROR_SUCCESS;
}
