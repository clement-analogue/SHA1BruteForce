/*
    SHA1BruteForce, brute-force attack to recover SHA-1 hashed password.
    Copyright (C) 2017  Clément Février

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    Contact informations:
    Email
     clement+dev@forumanalogue.fr
    Post address
     4 impasse de l'Abbaye
     38100 Grenoble
     FRANCE
*/

#ifndef _FUNCTIONS_H_
#define _FUNCTIONS_H_

/* Return the hash SHA-1 of a string (input)
   using libtomcrypt */
unsigned char * hashSHA1(const std::string & input);

/* Return the hash SHA-1 of a string (source)
   using Crypto++ */
//std::string generateHash(const std::string & source);

/* Seek for password, display the latter if found it
   and exit the program.
   This function launch the threads that will do the job.
   Depending on the number of threads,
   Each thread will test a different subset of possibilities.
   As a consequence,
   a greater or smaller number of threads can divide
   the set of possibilities in a way that it will reach faster
   or slower the actual password.
   However, there is noway to make an assumption on this number
   if there is no assumption on the password.
   Thus, the number of thread should be tuned
   to maximize device performances,
   i.e. the greatest number of operations per second.
   Parameters:
   * hash:     The hash to crack.
   * list:     List of all allowed characters.
   * COUNT:    Length of list.
   * L:        Maximum length of the password to test.
   * N_THREAD: Number of threads to launch. */
void findPassword(const unsigned char * hash, const std::string * list, const unsigned short int & COUNT, const unsigned char & L, const unsigned char N_THREAD);

/* Seek for password, display the latter if found it
   and exit the program.
   Parameters:
   * hash:     The hash to crack.
   * pass:     Current state of the password to build and test.
   * list:     List of all allowed characters.
   * COUNT:    Length of list.
   * L:        Maximum length of the password to test.
   * l:        Current length of the password to test.
   * N_THREAD: Number of threads to launch. */
void findPasswordThread(const unsigned char * hash, const std::string & pass, const std::string * list, const unsigned short int & COUNT, const unsigned char & L, const unsigned char & l, const unsigned char N_THREAD);

#endif
