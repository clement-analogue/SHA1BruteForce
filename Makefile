#    SHA1BruteForce, brute-force attack to recover SHA-1 hashed password.
#    Copyright (C) 2017  Clément Février
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    Contact informations:
#    Email
#     clement+dev@forumanalogue.fr
#    Post address
#     4 impasse de l'Abbaye
#     38100 Grenoble
#     FRANCE

all:ex

# Safe
# It should not display any warning.
# -Ofast activates some optimization flags.
# Other flags are added.
# -pipe decreases compilation time.
#
#CC= g++ -std=gnu++14 -Ofast -Wall -Wextra -pipe -fassociative-math -freciprocal-math -fno-signed-zeros -fno-trapping-math -frename-registers -funroll-loops -fopenmp -D_GLIBCXX_PARALLEL
#
# Same as above with flags specific for AMD Piledriver Family 15h.
#
CC= g++ -std=gnu++14 -Ofast -Wall -Wextra -pipe -fassociative-math -freciprocal-math -fno-signed-zeros -fno-trapping-math -frename-registers -funroll-loops -fopenmp -D_GLIBCXX_PARALLEL -march=bdver2 -msse -msse2 -msse3 -mmmx -m3dnow
#
# Use -fprofile-generate to generate a profile.
# Here for AMD Piledriver Family 15h.
#
#CC= g++ -std=gnu++14 -Ofast -Wall -Wextra -pipe -fassociative-math -freciprocal-math -fno-signed-zeros -fno-trapping-math -frename-registers -funroll-loops -fopenmp -D_GLIBCXX_PARALLEL -march=bdver2 -msse -msse2 -msse3 -mmmx -m3dnow -fprofile-generate
#
# Use -fprofile-use -fprofile-correction to use the profile.
# The second flag is needed for multithreading.
# Here for AMD Piledriver Family 15h.
#
#CC= g++ -std=gnu++14 -Ofast -Wall -Wextra -pipe -fassociative-math -freciprocal-math -fno-signed-zeros -fno-trapping-math -frename-registers -funroll-loops -fopenmp -D_GLIBCXX_PARALLEL -march=bdver2 -msse -msse2 -msse3 -mmmx -m3dnow -fprofile-use -fprofile-correction

link= -o

arg= -c -o

#lib= -lboost_thread -lboost_system -lcrypto++
lib= -lboost_thread -lboost_system -ltomcrypt

objets= main.o functions.o

ex: ${objets}
	@${CC} ${link} sha1 ${objets} ${lib}

%.o: %.cpp
	@${CC} ${arg} $@ $< ${lib}

clean:
	@rm -f *~ *.o gmon.out a.out *.s

mrproper: clean
	@rm -f sha1 err *.gcda
