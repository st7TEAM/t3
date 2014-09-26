#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string>
#include <string.h>
#include <dirent.h>

using namespace std;

std::string Str_trim(std::string temps)
{
	unsigned int pos = temps.find('\n');
	if(pos != string::npos)
		temps.replace(pos, 1, "");
	return temps;
}

bool DirectoryExists( const char* pzPath )
{
	DIR *pDir;
     	bool bExists = false;
	pDir = opendir (pzPath);
	if (pDir != NULL) {
		bExists = true;
		(void) closedir (pDir);
	}
	return bExists;
}

int TestMount(std::string dev)
{
	std::string cmd;
	int rc;
	system("mkdir /media/egamiboot");
	cmd = "mount " + dev + " /media/egamiboot > /dev/null 2>&1";
	rc = system(cmd.c_str());
	if (access("/media/egamiboot/EgamiBootI/.egamiboot", F_OK) != 0) {
		cmd = "umount " + dev + " /media/egamiboot > /dev/null 2>&1";
		rc = system(cmd.c_str());
		return 0;
	} else {
		return 1;
	}
}
int main(int argc, char **argv)
{
	FILE *f;
	char buf[256];
	int check = 0;
	int checkgo = 0;
	std::string EGAMIHOME = "/media/egamiboot";
	std::string TARGET = "Flash";
	std::string tmpstr = "";
	std::string tmpstr2 = "";
	std::string mydir = "";


	if (argc == 1) {
		checkgo = 1;
	} else if (argc == 2) {
		tmpstr = string(argv[1]);
		tmpstr2 = "ubifs";
		if (tmpstr == tmpstr2)
			checkgo = 1;
	
	}

// We have to run only if init is called whithout parameters
if (checkgo == 1) {


	check = system("/etc/init.d/sysfs.sh");
	check = system("/etc/init.d/modutils.sh");
//	check = system("/etc/init.d/udev start");

	system("mknod /dev/sda b  8 0");
	system("mknod /dev/sda1 b 8 1");
	system("mknod /dev/sda2 b 8 2");
	system("mknod /dev/sdb b  8 16");
	system("mknod /dev/sdb1 b 8 17");
	system("mknod /dev/sdb2 b 8 18");
	system("mknod /dev/sdc b  8 32");
	system("mknod /dev/sdc1 b 8 33");
	system("mknod /dev/sdc2 b 8 34");
	system("mknod /dev/sdd b  8 48");
	system("mknod /dev/sdd1 b 8 49");
	system("mknod /dev/sdd2 b 8 50");

	check = system("umount /media/sda1");
	check = system("umount /media/sdb1");
	check = system("umount /media/sdc1");
	check = system("umount /media/sdd1");
	sleep(2);
	check = system("/usr/bin/showiframe /usr/lib/enigma2/python/Plugins/Extensions/EGAMIBoot/egamiboot.mvi");
	
	DIR *d = opendir("/dev/");
	if (d)
	{
		while (struct dirent *e = readdir(d))
		{
//			if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
			if (strstr(e->d_name, "sd"))
			{
				mydir = "/dev/" + std::string(e->d_name);
				check = TestMount(mydir);
				if (check == 1)
					break;
			}
		}
	}
	closedir(d);

	sleep(1);
//	system ("cat /proc/stb/avs/0/colorformat > /proc/stb/avs/0/colorformat");
// bootmanager
	if (access("/usr/lib/enigma2/python/Plugins/Extensions/EGAMIBoot/bin/egamibm", F_OK) == 0)
		check = system("/usr/lib/enigma2/python/Plugins/Extensions/EGAMIBoot/bin/egamibm");
	
	
	f = fopen("/media/egamiboot/EgamiBootI/.egamiboot", "rt");
  	 if (f) {
		fgets(buf, 256, f);
		TARGET = string(buf);
		TARGET = Str_trim(TARGET);
      		fclose(f);
   	}

	if (TARGET == "Flash") {
		if (access("/boot/bootlogo.mvi", F_OK) == 0)
			check = system("/usr/bin/showiframe /boot/bootlogo.mvi > /dev/null 2>&1");
		else
			check = system("/usr/bin/showiframe /usr/share/bootlogo.mvi > /dev/null 2>&1");
		//sleep(1);
	} else {
		tmpstr = "/media/egamiboot/EgamiBootI/" + TARGET;
		if (DirectoryExists(tmpstr.c_str())) {
			tmpstr = "/media/egamiboot/EgamiBootI/" + TARGET + "/usr/share/bootlogo.mvi";
			if (access(tmpstr.c_str(), F_OK) == 0)
				tmpstr = "/usr/bin/showiframe " + tmpstr;
			else
				tmpstr = "/usr/bin/showiframe /media/egamiboot/EgamiBootI/" + TARGET + "/boot/bootlogo.mvi";
			check = system(tmpstr.c_str());
			//sleep(1);
	
			tmpstr = "/media/egamiboot/EgamiBootI/" + TARGET + "/dev";
			tmpstr2 = "/bin/mount -o bind /dev " + tmpstr;
			check = system(tmpstr2.c_str());

			tmpstr = "/media/egamiboot/EgamiBootI/" + TARGET + "/proc";
			tmpstr2 = "/bin/mount -o bind /proc " + tmpstr;
			check = system(tmpstr2.c_str());
			
			tmpstr = "/media/egamiboot/EgamiBootI/" + TARGET + "/sys";
			tmpstr2 = "/bin/mount -o bind /sys " + tmpstr;
			check = system(tmpstr2.c_str());

			tmpstr = "/media/egamiboot/EgamiBootI/" + TARGET + "/media/egamiboot";
			tmpstr2 = "rm -r" + tmpstr + " > /dev/null 2>&1";
			check = system(tmpstr2.c_str());
			
			tmpstr = "/media/egamiboot/EgamiBootI/" + TARGET + "/media/egamiboot";
			tmpstr2 = "mkdir " + tmpstr + " > /dev/null 2>&1";
			check = system(tmpstr2.c_str());
/*
			tmpstr = "/media/egamiboot /media/egamiboot/EgamiBootI/" + TARGET + "/egamiboot";
			tmpstr2 = "/bin/mount -o bind " + tmpstr;
			check = system(tmpstr2.c_str());

			tmpstr2 = "rmdir /media/egamiboot/EgamiBootI/" + TARGET + "/media/egamiboot";
			check = system(tmpstr2.c_str());

			tmpstr2 = "rm /media/egamiboot/EgamiBootI/" + TARGET + "/media/egamiboot";
			check = system(tmpstr2.c_str());
			
			tmpstr2 = "rm /media/egamiboot/EgamiBootI/" + TARGET + mydir;
			check = system(tmpstr2.c_str());
*/
			d = opendir("/media/");
			if (d)
				{
					while (struct dirent *e = readdir(d))
					{
						if (strcmp(e->d_name, "egamiboot"))
						{
							mydir = "/media/" + std::string(e->d_name);
							tmpstr = mydir + "/EgamiBootI/.egamiboot";
							if (access(tmpstr.c_str(), F_OK) == 0) 
							{
								break;
							}
						}
					}
					closedir(d);
				}

			check = 0;
			tmpstr = "/media/egamiboot/EgamiBootI/" + TARGET + "/etc/init.d/bootmisc.sh";
			f = fopen(tmpstr.c_str(), "r");
			if (f) 
			{
				while (fgets(buf, 256, f)) {
					if (strstr(buf, "egamiboot"))
						check = 1;
				}
					fclose(f);
			}
			
			if (check == 0) 
			{
				tmpstr = "/media/egamiboot/EgamiBootI/" + TARGET + "/etc/init.d/bootmisc.sh";
				f = fopen(tmpstr.c_str(), "r");
				tmpstr = "/media/egamiboot/EgamiBootI/" + TARGET + "/etc/init.d/bootmisc.tmp";
				FILE *f1 = fopen(tmpstr.c_str(), "w+");
				if (f && f1) 
				{
					while (fgets(buf, 256, f)) 
					{
						if (!strstr(buf, "exit 0"))
						{
							fputs(buf, f1);
						}
						else
						{							
							tmpstr = "if [ ! -d \"/media/egamiboot\" ]\\; then\n";
							tmpstr += "	mkdir /media/egamiboot\n";
							tmpstr += "fi\n";
							tmpstr += "DEVICES1=`find /dev/sd??`\n";
							tmpstr += "for DEVICE in $DEVICES1;\n";
							tmpstr += "	do\n";
							tmpstr += "	if [ ! -e /media/egamiboot/EgamiBootI/.egamiboot  ]\\; then\n";
							tmpstr += "		mount $DEVICE /media/egamiboot\n";
							tmpstr += "	fi\n";
							tmpstr += "	if [ ! -e /media/egamiboot/EgamiBootI/.egamiboot  ]\\; then\n";
							tmpstr += "		umount /media/egamiboot\n";
							tmpstr += "	else\n";
							tmpstr += "		break\n";
							tmpstr += "	fi\n";
							tmpstr += "	done\n";
							tmpstr += "umount " + mydir + "\n";
							tmpstr += "if ! mountpoint -q" + mydir + "\\; then\n";
        					tmpstr += "rm -r " + mydir + "\n";
        					tmpstr += "mkdir " + mydir + "\n";
        					tmpstr += "mount $DEVICE " + mydir + "\n";
        					tmpstr += "fi\n\n";
							fputs(tmpstr.c_str(), f1);
							fputs(buf, f1);
						}
					}
							
					fclose(f);
					fclose(f1);
					tmpstr = "mv -f /media/egamiboot/EgamiBootI/" + TARGET + "/etc/init.d/bootmisc.tmp /media/egamiboot/EgamiBootI/" + TARGET + "/etc/init.d/bootmisc.sh";
					check = system(tmpstr.c_str());
					tmpstr = "chmod 0775 /media/egamiboot/EgamiBootI/" + TARGET + "/etc/init.d/bootmisc.sh";
					check = system(tmpstr.c_str());
				}
			}
		
			tmpstr = "/media/egamiboot/EgamiBootI/" + TARGET;
			chdir (tmpstr.c_str());
			chroot(".");
		}
	}
	
	unlink("/&1");

}

 	execv("/sbin/init.sysvinit", argv);

	return 0;
}


