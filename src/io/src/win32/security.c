/*
   Copyright (c) 2024-2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <win32/nt.h>

#include <os.h>
#include <ptr.h>

#define __OS_BASIC_PERMISSIONS   (FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE | DELETE)
#define __OS_READ_PERMISSIONS    (FILE_READ_DATA | FILE_READ_EA | __OS_BASIC_PERMISSIONS)
#define __OS_WRITE_PERMISSIONS   (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_DELETE_CHILD | __OS_BASIC_PERMISSIONS)
#define __OS_EXECUTE_PERMISSIONS (FILE_EXECUTE | __OS_BASIC_PERMISSIONS)

// Only give these to system, admins and user
#define __OS_EXTRA_PERMISSIONS (WRITE_DAC | WRITE_OWNER)
#define __OS_ALL_PERMISSIONS   (__OS_READ_PERMISSIONS | __OS_WRITE_PERMISSIONS | __OS_EXECUTE_PERMISSIONS | __OS_EXTRA_PERMISSIONS)

static ACCESS_MASK determine_access_mask(mode_t mode)
{
	ACCESS_MASK access = 0;

	if (mode & 0001)
	{
		access |= __OS_READ_PERMISSIONS;
	}
	if (mode & 0002)
	{
		access |= __OS_WRITE_PERMISSIONS;
	}
	if (mode & 0004)
	{
		access |= __OS_EXECUTE_PERMISSIONS;
	}

	return access;
}

static mode_t determine_mode(ACCESS_MASK access)
{
	mode_t perms = 0;

	if ((access & FILE_ACCESS_READ) == FILE_ACCESS_READ)
	{
		perms |= PERM_USER_READ;
	}
	if ((access & FILE_ACCESS_WRITE) == FILE_ACCESS_WRITE)
	{
		perms |= PERM_USER_WRITE;
	}
	if ((access & __FILE_ACCESS_EXECUTE) == __FILE_ACCESS_EXECUTE)
	{
		perms |= PERM_USER_EXECUTE;
	}

	return perms;
}

void *_os_security_descriptor(mode_t mode, uint32_t directory)
{
	/*
	  Size of SECURITY_DESCRIPTOR_RELATIVE : 20
	  Size of ACL Header                   : 8
	  Size of (NT AUTHORITY\SYSTEM)ACE     : 20 (1 subauthorities)
	  Size of (BUILTIN\Administrators) ACE : 24 (2 subauthorities)
	  Size of (BUILTIN\Users) ACE          : 24 (2 subauthorities)
	  Size of (Everyone) ACE               : 20 (1 subauthorities)
	  Size of User ACE                     : 36 (5 subauthorities usually) or 76 (15 max subauthorities)
	  Total                                : 152 bytes or 192 bytes max
	*/

	const ULONG size_of_sd_buffer = 256;

	PISECURITY_DESCRIPTOR_RELATIVE security_descriptor = NULL;
	SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY world_authority = SECURITY_WORLD_SID_AUTHORITY;

	VOID *sd_buffer = (char *)RtlAllocateHeap(NtCurrentProcessHeap(), HEAP_ZERO_MEMORY, size_of_sd_buffer);

	if (sd_buffer == NULL)
	{
		return NULL;
	}

	security_descriptor = sd_buffer;
	security_descriptor->Revision = SECURITY_DESCRIPTOR_REVISION;
	security_descriptor->Control = SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED | SE_DACL_PRESENT | SE_SELF_RELATIVE;

	// No need to set other fields to zero as we are memsetting anyway.
	// Put the DACL at the end.
	security_descriptor->Dacl = sizeof(SECURITY_DESCRIPTOR_RELATIVE);

	PACL acl = PTR_OFFSET(sd_buffer, security_descriptor->Dacl);
	RtlCreateAcl(acl, size_of_sd_buffer - sizeof(SECURITY_DESCRIPTOR_RELATIVE), ACL_REVISION);

	ULONG ace_flags = (directory == 0 ? 0 : OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);

	// Give adminstrators and the system full permissions always.
	BYTE ntsystem_sid_buffer[SECURITY_SID_SIZE(1)] = {0};
	BYTE adminstrators_sid_buffer[SECURITY_SID_SIZE(2)] = {0};

	// NT AUTHORITY\SYSTEM
	RtlInitializeSidEx((PSID)ntsystem_sid_buffer, &nt_authority, 1, SECURITY_LOCAL_SYSTEM_RID);
	RtlAddAccessAllowedAceEx(acl, ACL_REVISION, ace_flags, __OS_ALL_PERMISSIONS, (PSID)ntsystem_sid_buffer);

	// BUILTIN\Administrators
	RtlInitializeSidEx((PSID)adminstrators_sid_buffer, &nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS);
	RtlAddAccessAllowedAceEx(acl, ACL_REVISION, ace_flags, __OS_ALL_PERMISSIONS, (PSID)adminstrators_sid_buffer);

	if (mode & 0070)
	{
		ULONG length = 0;

		BYTE buffer[128] = {0};
		BYTE user_sid_buffer[SECURITY_SID_SIZE(SID_MAX_SUB_AUTHORITIES)] = {0};

		NtQueryInformationToken(NtCurrentProcessToken(), TokenUser, buffer, 128, &length);
		RtlCopySid(SECURITY_SID_SIZE(SID_MAX_SUB_AUTHORITIES), (PSID)user_sid_buffer, ((PTOKEN_USER)buffer)->User.Sid);

		// Don't add user permission if we are admin or system as we have already added them.
		if (!(RtlEqualSid(user_sid_buffer, adminstrators_sid_buffer) || RtlEqualSid(user_sid_buffer, ntsystem_sid_buffer)))
		{
			// Always give basic permissions to the owner.
			// Give ability to change owner and dacl to the user.
			RtlAddAccessAllowedAceEx(acl, ACL_REVISION, ace_flags, determine_access_mask((mode & 0700) >> 6) | __OS_EXTRA_PERMISSIONS,
									 (PSID)user_sid_buffer);
		}
	}
	if (mode & 0070)
	{
		// BUILTIN\Users
		BYTE users_sid_buffer[SECURITY_SID_SIZE(2)] = {0};

		RtlInitializeSidEx((PSID)users_sid_buffer, &nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS);
		RtlAddAccessAllowedAceEx(acl, ACL_REVISION, ace_flags, determine_access_mask((mode & 0070) >> 3), (PSID)users_sid_buffer);
	}
	if (mode & 0007)
	{
		// Everyone
		BYTE everyone_sid_buffer[SECURITY_SID_SIZE(1)] = {0};

		RtlInitializeSidEx((PSID)everyone_sid_buffer, &world_authority, 1, SECURITY_WORLD_RID);
		RtlAddAccessAllowedAceEx(acl, ACL_REVISION, ace_flags, determine_access_mask(mode & 0007), (PSID)everyone_sid_buffer);
	}

	return security_descriptor;
}

void _os_access(handle_t handle, void *st)
{
	NTSTATUS status = 0;

	BYTE security_buffer[512];
	BYTE user_buffer[128] = {0};
	ULONG length = 0;

	stat_t *stat = st;
	mode_t allowed_access = 0, denied_access = 0;

	status = NtQuerySecurityObject(handle, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
								   security_buffer, sizeof(security_buffer), &length);

	if (status != STATUS_SUCCESS)
	{
		return;
	}

	SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY world_authority = SECURITY_WORLD_SID_AUTHORITY;

	BYTE ntsystem_sid_buffer[SECURITY_SID_SIZE(1)] = {0};
	BYTE adminstrators_sid_buffer[SECURITY_SID_SIZE(2)] = {0};
	BYTE current_user_sid_buffer[SECURITY_SID_SIZE(SID_MAX_SUB_AUTHORITIES)] = {0};
	BYTE users_sid_buffer[SECURITY_SID_SIZE(2)] = {0};
	BYTE everyone_sid_buffer[SECURITY_SID_SIZE(1)] = {0};

	RtlInitializeSidEx((PSID)ntsystem_sid_buffer, &nt_authority, 1, SECURITY_LOCAL_SYSTEM_RID);
	RtlInitializeSidEx((PSID)adminstrators_sid_buffer, &nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS);
	RtlInitializeSidEx((PSID)users_sid_buffer, &nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS);
	RtlInitializeSidEx((PSID)everyone_sid_buffer, &world_authority, 1, SECURITY_WORLD_RID);

	NtQueryInformationToken(NtCurrentProcessToken(), TokenUser, user_buffer, 128, &length);
	RtlCopySid(SECURITY_SID_SIZE(SID_MAX_SUB_AUTHORITIES), (PSID)current_user_sid_buffer, ((PTOKEN_USER)user_buffer)->User.Sid);

	PISECURITY_DESCRIPTOR_RELATIVE security_descriptor = (PISECURITY_DESCRIPTOR_RELATIVE)security_buffer;
	PISID owner = (PISID)(security_buffer + security_descriptor->Owner);
	PISID group = (PISID)(security_buffer + security_descriptor->Group);
	PACL acl = (PACL)(security_buffer + security_descriptor->Dacl);

	size_t acl_read = 0;

	// Set the uid, gid as the last subauthority of their respective SIDs.
	stat->st_uid = owner->SubAuthority[owner->SubAuthorityCount - 1];
	stat->st_gid = group->SubAuthority[group->SubAuthorityCount - 1];

	// Treat "NT AUTHORITY\SYSTEM" and "BUILTIN\Administrators" as root.
	if (RtlEqualSid(owner, (PSID)adminstrators_sid_buffer) || RtlEqualSid(owner, (PSID)ntsystem_sid_buffer))
	{
		stat->st_uid = 0;
	}
	if (RtlEqualSid(group, (PSID)adminstrators_sid_buffer) || RtlEqualSid(group, (PSID)ntsystem_sid_buffer))
	{
		stat->st_gid = 0;
	}

	// Iterate through the ACLs
	// Order should be (NT AUTHORITY\SYSTEM), (BUILTIN\Administrators), Current User ,(BUILTIN\Users), Everyone
	for (int i = 0; i < acl->AceCount; ++i)
	{
		PISID sid = NULL;
		PACE_HEADER ace_header = PTR_OFFSET(acl, sizeof(ACL) + acl_read);

		// Only support allowed and denied ACEs
		// Both ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE have ACE_HEADER at the start.
		// Type casting of pointers here will work.
		if (ace_header->AceType == ACCESS_ALLOWED_ACE_TYPE)
		{
			PACCESS_ALLOWED_ACE allowed_ace = (PACCESS_ALLOWED_ACE)ace_header;
			sid = (PISID) & (allowed_ace->SidStart);
			if (RtlEqualSid(sid, (PSID)current_user_sid_buffer))
			{
				allowed_access |= determine_mode(allowed_ace->Mask);
			}
			else if (RtlEqualSid(sid, (PSID)users_sid_buffer))
			{
				allowed_access |= determine_mode(allowed_ace->Mask) >> 3;
			}
			else if (RtlEqualSid(sid, (PSID)everyone_sid_buffer))
			{
				allowed_access |= determine_mode(allowed_ace->Mask) >> 6;
			}
			else
			{
				// Unsupported SID or SYSTEM or Administrator, ignore
			}
		}
		else if (ace_header->AceType == ACCESS_DENIED_ACE_TYPE)
		{
			PACCESS_DENIED_ACE denied_ace = (PACCESS_DENIED_ACE)ace_header;
			sid = (PISID) & (denied_ace->SidStart);
			if (RtlEqualSid(sid, (PSID)current_user_sid_buffer))
			{
				denied_access |= determine_mode(denied_ace->Mask);
			}
			else if (RtlEqualSid(sid, (PSID)users_sid_buffer))
			{
				denied_access |= determine_mode(denied_ace->Mask) >> 3;
			}
			else if (RtlEqualSid(sid, (PSID)everyone_sid_buffer))
			{
				denied_access |= determine_mode(denied_ace->Mask) >> 6;
			}
			else
			{
				// Unsupported SID or SYSTEM or Administrator, ignore
			}
		}
		else
		{
			// Unsupported ACE type
		}
		acl_read += ace_header->AceSize;
	}

	stat->st_mode = allowed_access & ~denied_access;
}