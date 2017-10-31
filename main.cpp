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
#include <sstream>  // std::istringstream
#include <vector>   // std::vector
#include <ios>      // std::hex
#include <iostream> // std::cout
#include <ostream>  // std::endl
#include <cstdio>   // std::printf

#include "functions.h" // findPassword

/* Seek for a password corresponding to a given SHA-1 hash.
   Complexity: It is a simple brute-force algorithm,
               so the complexity increases exponentially
               with the size of the password.
   Multithreading: On a N_CORE computer,
                   if SEQTIME is the maximum time
                   when launched with one thread,
                   then the maximum time is
                   SEQTIME / N_TREAD when N_THREAD < N_CORE
                   and SEQTIME / N_CORE when N_THREAD > N_CORE
   Parameters to set before compiling:
   * HASH:      The SHA-1 hash.
                Two accepted format:
                1/ Without spaces, as usually stored.
                   You need to ensure
                   that it is 40 character-long.
                   Example for the password ZZZ
                   116ff222a3b49b63348d7782e4b43ffe2dcbb198
                2/ With spaces.
                   No restriction on the length of the string.
                   But you need to ensure to have
                   20 spaced-separated hexadecimal numbers.
                   It is the format used to display hashes
                   in this program.
                   Example for the password ZZZZZZ
                   18 f3 f 1b a4 c6 2e 2b 46 e 69 33 6 b3 9a d e2 7d 74 7c
   * MaxLength: Maximum length of the password to test.
   * N_THREAD:  Number of threads to launch.
                The program will launch at most
                a number of thread corresponding
                to the number of character to test.
                In other words, the length of list.
                In this case, it is 95. */
int main ()
{
 // Number of threads to launch.
 const unsigned char N_THREAD = 64;
 // Max length of password.
 const unsigned char MaxLength = 4;
 // SHA-1 hash to crack.
 // Below few examples and their corresponding password.
 // ZZZ
 //std::string HASH = "11 6f f2 22 a3 b4 9b 63 34 8d 77 82 e4 b4 3f fe 2d cb b1 98";
 std::string HASH = "116ff222a3b49b63348d7782e4b43ffe2dcbb198";
 // ZZZZ
 //std::string HASH = "98 65 d4 83 bc 5a 94 f2 e3 0 56 fc 25 6e d3 6 6a f5 4d 4";
 // ZZZZZ
 //std::string HASH = "f8 88 fa 8a 61 ba 9a 53 a4 5f 4 a 4b bb 8b 2f c1 f6 44 44";
 // ZZZZZZ
 //std::string HASH = "18 f3 f 1b a4 c6 2e 2b 46 e 69 33 6 b3 9a d e2 7d 74 7c";
 //std::string HASH = "18 f3 f 1b a4 c6 2e 2b 46 e 69 33 6 b3 9a d e2 7d 74 7c";
 // If set, ignore HASH and compute test's SHA-1 hash and attempt to crack it.
 const std::string test = "";
 // Pointer used to store the SHA-1 hash.
 unsigned char * hash;
 // std::vector used to create hash.
 // Warning: It cannot be put inside the else's scope
 // otherwise the pointer is destroyed when leaving it.
 std::vector< unsigned char > bytes;
 // If a password is manually set,
 // then generate its SHA-1 hash and attempt to crack it.
 // It can be used for testing and benchmarking purposes.
 if(test != "")
 {
  std::cout<<"* Test password:"<<std::endl;
  std::cout<<test<<std::endl;
  //const std::string hash = generateHash(test);
  // Generate the SHA-1 hash of test.
  hash = hashSHA1(test);
 }
 else
 {
  // Convert HASH to the correct format if needed.
  // Only start to search for space at position 37.
  // If find() return std::string::npos,
  // then find() did not find any space.
  if(HASH.find(" ", 37) == std::string::npos)
  {
   // Add space every 2 characters starting from the end.
   std::string space = " ";
   for(unsigned char i = 19; i > 0; --i)
   {
    HASH.insert(2 * i, space);
   }
  }
  // Convert HASH from std::string to unsigned char *.
  std::istringstream hex_chars_stream(HASH);
  unsigned int c;
  while (hex_chars_stream >> std::hex >> c)
  {
      bytes.push_back(c);
  }
  // Extract the pointer to the SHA-1 hash
  // from the std::vector container.
  hash = bytes.data();
 }
 // Display the input SHA-1 hash.
 std::cout<<"* Hash SHA1:"<<std::endl;
 for (int x = 0; x < 20; ++x)
 {
  std::printf("%x ", hash[x]); //Hex-format
 }
 std::cout<<std::endl;
 // list: Create the list of all characters to test.
 std::string * list = new std::string [127 - 33 + 1];
 // count: Increment used to access list element in the loop.
 //        Also used to pass the length of the list
 //        to findPassword.
 unsigned short int count = 0;
 // First item is "".
 // Used to build password to test smaller than MaxLength.
 list[0] = "";
 // Increment count;
 count = 1;
 // Assign all possible char to list.
 // In this case, all from 33 to 126 included.
 // The reverted order is used to test in priority
 // lowercase-based passwords.
 for(unsigned short int i = 126; i > 32; --i)
 {
  // Convert the dec value of i to char.
  list[count] = (char)i;
  // Increment count.
  ++count;
 }
 // Find the password, display and exit if found it.
 // 2 possible reasons it does not find it:
 // 1/ The password length is greater than MaxLength.
 // 2/ The list does not contain at least one character
 //    of the password.
 findPassword(hash, list, count, MaxLength, N_THREAD);
 // Exit without error.
 return 0;
}
