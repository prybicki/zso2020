- open
- write
- read
- fstat
- lseek
- locks
- fsync
- ftrunc
- close
--------
- p*v

file_size = 30
t 10
t 20
l 0
r 20 -> to powinno pokazać zera od 10+

- FSYNC NIE MOZE ZMIENIAC f_pos!!!
	- I nie zmienia..


- Troszkę brakuje spójności w nazewnictwie (zso_ / __vfs...)
- Obejrzyj callgraph sync (a najlepiej wszystkiego)


=== fsync/ftrunc
open ustawia file_size zgodnie z f_inode->i_size

__vfs_buffered_write aktualizuje

read obcina odczyt do file_size

ftruncate aktualizuje i usuwa niepotrzebne wpisy (niektóre trzeba przyciąć)

fsync robi prawdziwego pliku ftrunc

