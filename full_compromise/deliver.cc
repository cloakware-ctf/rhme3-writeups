
#include <errno.h>
#include <fcntl.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/time.h>
#include <string.h>

int set_interface_attribs(int fd, int speed) {
    struct termios tty;

    if (tcgetattr(fd, &tty) < 0) {
        printf("Error from tcgetattr: %s\n", strerror(errno));
        return -1;
    }

    cfsetospeed(&tty, (speed_t)speed);
    cfsetispeed(&tty, (speed_t)speed);

    tty.c_cflag |= (CLOCAL | CREAD);    /* ignore modem controls */
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;         /* 8-bit characters */
    tty.c_cflag &= ~PARENB;     /* no parity bit */
    tty.c_cflag &= ~CSTOPB;     /* only need 1 stop bit */
    tty.c_cflag &= ~CRTSCTS;    /* no hardware flowcontrol */

    /* setup for non-canonical mode */
    tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    tty.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    tty.c_oflag &= ~OPOST;

    /* fetch bytes as they become available */
    tty.c_cc[VMIN] = 1;
    tty.c_cc[VTIME] = 1;

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        printf("Error from tcsetattr: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

void set_mincount(int fd, int mcount) {
    struct termios tty;

    if (tcgetattr(fd, &tty) < 0) {
        printf("Error tcgetattr: %s\n", strerror(errno));
        return;
    }

    tty.c_cc[VMIN] = mcount ? 1 : 0;
    tty.c_cc[VTIME] = 5;        /* half second timer */

    if (tcsetattr(fd, TCSANOW, &tty) < 0)
        printf("Error tcsetattr: %s\n", strerror(errno));
}

void pulseChar(int fd, char c) {
	for (int i=0; i<c; i++) {
		write(fd, ".", 1);
		usleep(10*1000);
		tcdrain(fd);    // delay for output
	}
	printf("%c", c);fflush(stdout);
}

void pulseSeparator(int fd) {
	usleep(4*1000*1000);
}

int main(int argc, char* argv[]) {
	int fd;
	int len;
	char buf[800];
	int used;
	char *portname;
	char *passcode;
	int pcLen;

	if (argc <= 2) {
		fprintf(stderr, "Usage %s: <serial port> <passcode>\n", argv[0]);
		return -1;
	}
    portname = argv[1];
    passcode = argv[2];
	pcLen = strlen(passcode);
	printf("sending %d characters of passcode\n", pcLen);

    fd = open(portname, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0) {
        printf("Error opening %s: %s\n", portname, strerror(errno));
        return -1;
    }
    /*baudrate 115200, 8 bits, no parity, 1 stop bit */
    set_interface_attribs(fd, B115200);
    //set_mincount(fd, 0);                /* set to pure timed read */

    /**********************************************************************/
	printf("clearing init messages\n"); // {{{
	used = 0;
	do {
        len = read(fd, &(buf[used]), sizeof(buf) - used - 1);
        if (len > 0) {
            buf[used+len] = 0;
            printf("%s", &(buf[used]));
			used += len;
        } else if (len < 0) {
            printf("Error from read: %d: %s\n", len, strerror(errno));
        }

		if (strstr(buf, "Type 'test' to run analog test.\r\n")) {
			break;
		}
	} while (1); // }}}

    /**********************************************************************/
	printf("sending data\n"); // {{{
    len = write(fd, "*\n", 2);
    if (len != 2) {
        printf("Error from write: %d, %d\n", len, errno);
    }
	for (int i=0; i<pcLen; i++) {
		pulseSeparator(fd);
		pulseChar(fd, passcode[i]);
	}
	printf("\n");
	pulseSeparator(fd);
    len = write(fd, "*", 1);
    tcdrain(fd);    // }}}

    /**********************************************************************/
    printf("getting reply\n"); // {{{
    do {
        len = read(fd, buf, sizeof(buf) - 1);
        if (len > 0) {
            buf[len] = 0;
            printf("%s", buf);
        } else if (len < 0) {
            printf("Error from read: %d: %s\n", len, strerror(errno));
        }
        /* repeat read to get full message */
    } while (1); // }}}

	return 0;
}

