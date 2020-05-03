- Figure out if there's any locking neccessary to access file.f_flags;
- PAMIĘTAJ TEŻ O EINTR!
- Zwolnij cały ten syf w close
- Używaj kmalloc dla małych alokacji
- flatten zso_write_buffer into file? file wasttes more space if unused
- 

Rozważmy taką sytuację:
- proces A otwiera plik X z flagą O_BUFFERED_WRITE, wykonuje write
- proces B otwiera plik X, wykonuje ftruncate, zamyka plik
- proces A wykonuje read

Co powinien zrobić read w kontekście procesu A?:
a) gdy read zawiera się całkowicie w zakresie wcześniej zapisanym przez proces A
b) wpp.? (tzn. read musi przeczytać kawałek fizycznego pliku, który już nie istnieje)

Prosta zachłanna implementacja kompletuje dane czytając (być może naprzemiennie) z bufora i fizycznego pliku, w przypadku a) taka operacja by się udała, natomiast w b) pewien read() z fizycznego pliku >>> no właśnie, błąd czy po prostu nic by nie zwróciła?



Read mógłby sprawdzać 
===
Czy read sprawdza rozmiar pliku zanim zacznie czytać? W którym momencie dostanie kuku jak zacznie czytać całkowicie poza zakresem pliku?




