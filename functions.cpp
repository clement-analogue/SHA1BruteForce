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

//#include <crypto++/sha.h>
//#include <crypto++/hex.h>

#include <string>   // std::string
#include <iostream> // std::cout, ostream (std::endl)
#include <cstddef>  // size_t
#include <cstdio>   // std::printf
#include <cstdlib>  // EXIT_SUCCESS, exit

#include <boost/thread.hpp> // boost::thread_group, boost::bind

#include <tomcrypt.h> // sha1_desc, hash_state, sha1_init, sha1_process

#include "functions.h"

/**
 * Hashes a given input string using the SHA1 algorithm
 * @param input The input sequence pointer
 * @param inputSize The size of the input sequence
 * @return A new[]-allocated pointer to the resulting data. 20 bytes long.
 */
unsigned char * hashSHA1(const std::string & input)
{
 //Initial
 unsigned char * hashResult = new unsigned char[sha1_desc.hashsize];
 //Initialize a state variable for the hash
 hash_state md;
 sha1_init(&md);
 //Process the text - remember you can call process() multiple times
 sha1_process(&md, (const unsigned char*) input.c_str(), input.size());
 //Finish the hash calculation
 sha1_done(&md, hashResult);
 // Return the result
 return hashResult;
}

/*std::string generateHash(const std::string & source)
{
 CryptoPP::SHA1 hash;
 byte digest[CryptoPP::SHA1::DIGESTSIZE];
 hash.CalculateDigest(digest, (const byte*)source.c_str(), source.size());
 std::string output;
 CryptoPP::HexEncoder encoder;
 CryptoPP::StringSink test = CryptoPP::StringSink(output);
 encoder.Attach(new CryptoPP::StringSink(output));
 encoder.Put(digest, sizeof(digest));
 encoder.MessageEnd();
 return output;
}*/

void findPassword(const unsigned char * hash, const std::string * list, const unsigned short int & COUNT, const unsigned char & L, const unsigned char N_THREAD)
{
 // Create a group of threads
 boost::thread_group t;
 for(unsigned short int i = 0; i < COUNT; ++i)
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
   std::cout<<"progress: "<<100 * i / (double)COUNT <<"%"<<std::endl;
  }
 }
 // Wait for remaining threads to finish
 t.join_all();
}

void findPasswordThread(const unsigned char * hash, const std::string & pass, const std::string * list, const unsigned short int & COUNT, const unsigned char & L, const unsigned char & l, const unsigned char N_THREAD)
{
 // If the password to test is build,
 // test if it is the correct one
 if(l == L)
 {
  // Hash the pass word to test
  unsigned char * sha1 = hashSHA1(pass);
  // Test if hashes match
  // Assume that the correct password expected if shown otherwise
  bool found = true;
  for(unsigned char i = 0; i < 20; ++i)
  {
   // This condition is strictly equivalent to
   // if(sha1[i] ^ hash[i])
   // They need -O3 to be efficient
   // because it is reduced from 16 to only 3 instructions
   // in assembler.
   // Extra labels of -Ofast does not affect this instruction.
   if(sha1[i] != hash[i])
   {
    found = false;
    // If is not a match, there is no need to keep testing.
    break;
   }
  }
  // Free the memory of the test hash
  // because it is not needed anymore.
  delete [] sha1;
  // If it is a match, then display the password and hash,
  // and exit the program as there is not need to keep looking
  // for the password.
  // It is not thread safe,
  // so we cannot free the memory of the variable hash
  // otherwise other threads will try to access the pointer
  // leading to a segmentation fault.
  if(found)
  {
   // Display once again the hash.
   std::cout<<"* Hash SHA1:"<<std::endl;
   for (unsigned char x = 0; x < 20; ++x)
   {
    std::printf("%x ", hash[x]); //Hex-format
   }
   std::cout<<std::endl;
   // Display the password.
   std::cout<<"* Password:"<<std::endl<<pass<<std::endl;
   // Exit the program regardless the state of the other threads.
   exit(EXIT_SUCCESS);
  }
 }
 else
 {
  // If the password is not build yet,
  // keep appending characters.
  for(unsigned short int i = 0; i < COUNT; ++i)
  {
   // pass + list[i]
   // adds a new letter to the password to test.
   // Increment l + 1
   // because a new character is added to the password to test.
   findPasswordThread(hash, pass + list[i], list, COUNT, L, l + 1, N_THREAD);
  }
 }
}
