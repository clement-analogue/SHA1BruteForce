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

#include <string>   // std::string
#include <iostream> // std::cout, ostream (std::endl),
                    // io (std::hex)
#include <cstdlib>  // EXIT_SUCCESS, exit

#include "functions.h"

/*std::string generateHash(const auto & source)
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

void findPasswordThread(const unsigned char * hash, const std::string & pass, const std::string * list, const unsigned char & COUNT, const unsigned char & L, const unsigned char & l, const unsigned char & N_THREAD)
{
 // If the password to test is build,
 // test if it is the correct one
 if(l == L)
 {
  // Hash the pass word to test
  const auto sha1 = hashSHA1(pass);
  // Test if hashes match
  // Assume that the correct password expected if shown otherwise
  auto found = true;
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
   for(unsigned char x = 0; x < 20; ++x)
   {
    // Hex-format
    std::cout<<std::hex<<(unsigned short int)hash[x]<<" ";
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
  for(unsigned char i = 0; i < COUNT; ++i)
  {
   // pass + list[i]
   // adds a new letter to the password to test.
   // Increment l + 1
   // because a new character is added to the password to test.
   findPasswordThread(hash, pass + list[i], list, COUNT, L, l + 1, N_THREAD);
  }
 }
}
