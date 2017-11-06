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

#include <string>   // std::string
#include <iostream> // std::cout, ostream (std::endl)

#include <boost/thread.hpp> // boost::thread_group, boost::bind

//#include <crypto++/sha.h>
//#include <crypto++/hex.h>

#include <tomcrypt.h> // sha1_desc, hash_state, sha1_init, sha1_process

/* Hashes a given input string using the SHA-1 algorithm
   using libtomcrypt
   Parameter:
   * The input sequence pointer
   Returns:
   * A 20 bytes long new[]-allocated pointer
     to the resulting data. */
unsigned char * hashSHA1(const auto & input)
{
 // Initial
 auto * hashResult = new unsigned char [sha1_desc.hashsize];
 // Initialize a state variable for the hash
 hash_state md;
 sha1_init(&md);
 // Process the text
 sha1_process(&md, (const decltype(hashSHA1(input))) input.c_str(), input.size());
 // Finish the hash calculation
 sha1_done(&md, hashResult);
 // Return the result
 return hashResult;
}

/* Return the hash SHA-1 of a string (source)
   using Crypto++ */
//std::string generateHash(const auto & source);

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
void findPasswordThread(const unsigned char * hash, const std::string & pass, const std::string * list, const unsigned char & COUNT, const unsigned char & L, const unsigned char & l, const unsigned char & N_THREAD);

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
void findPassword(const auto hash, const auto list, const auto & COUNT, const auto & L, const auto & N_THREAD)
{
 // Create a group of threads
 boost::thread_group t;
 for(unsigned char i = 0; i < COUNT; ++i)
 {
  // Launch a thread
  // Initiate the recursive function with the first letter
  t.create_thread(boost::bind(findPasswordThread, hash, list[i], list, COUNT, L, 1, N_THREAD));
  // Wait until N_THREAD finish before launching news ones
  if((i % N_THREAD) == (N_THREAD - 1))
  {
   // Do not continue before all launched threads finish
   t.join_all();
   // Display a progress to standard output
   std::cout<<"progress: "<<100 * i / (float)COUNT <<"%"<<std::endl;
  }
 }
 // Wait for remaining threads to finish
 t.join_all();
}

#endif
