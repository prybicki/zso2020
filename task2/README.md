## Pliki

- fs/zso.c - Większość kodu, pozostałe to drobne wpięcia.
- include/linux/fs.h - Definicje, prototypy.
Dodane funkcje / struktury są prefixowane zso_*.

## Struktury danych

Open z flagą O_BUFFERED_WRITE skutkuje alokacją pomocniczej struktury danych i podpięcie jej do deskryptora pliku (struct file).

Zawiera prywatną stertę na rzecz alokacji struktur opisujących ciągłe obszary zapisane przez użytkownika, listę wszystkich ów struktur, mutex, chroniący te dane przed współbieżną modyfikacją, oraz buforowany rozmiar pliku, który jest modyfikowany przez ftruncate (zarówno zwiększany jak i zmniejszany) oraz przez zapisy (tylko zwiększany).

```
struct zso_write_buffer {
	struct kmem_cache* heap;   // struct zso_write_entry
	struct list_head entries;  // struct zso_write_entry
	struct mutex mutex;  // guards all members of this struct
	loff_t file_size;
};
```

Ciągły obszar zapisany przez użytkownika jest przechowywany jako:

```
struct zso_write_entry {
	char* data;  // allocated with kvmalloc
	loff_t beg;  // offsets from the file beginning
	loff_t end;
	struct list_head list_node;
};
```

## Operacje

### (p)write: zso_buffered_write

1) Znajdź pierwszy i ostatni (first, last) spójny obszar (zso_write_entry), któr zawiera się w / bezpośrednio sąsiaduje z obszarem do zapisania. Równocześnie wykryj przypadek zapisania wewnątrz istniejącego już zso_write_entry (*)
2) Jeżeli zajdzie (*), zmodyfikuj bufor, koniec.
3) Przygotuj nowy zso_write_entry, skopiuj do niego dane właściwe oraz z (first, last) oraz usuń zso_write_entry(-ies) pomiędzy first oraz last włącznie. Dla przykładu:

```
Przed zapisem:
   AAA BBB
Zapis:
     XXX
Wynik: (AAA, BBB) to odp. (first, last)
   AAXXXBB
```

Wówczas zso_write_entry(-ies) przechowujące AAA oraz BBB zostaną usunięte. Kod oczywiście uwzlędnia wszystkie możliwe przypadki.
4) Dodaj nowy zso_write_entry na listę
5) Uaktualnij pozycję końca pliku.

### (p)read: zso_buffered_read

1) Jeżeli odczyt wykracza poza buforowany koniec pliku, to go ucinamy.
2) ~Przeglądamy buforowane obszary po kawałku i czytamy, w zależności od sytuacji (tzn. jaki kolejny obszar widzimy) albo z fizycznego pliku, albo z buforowanego obszaru, albo sięgamy po kolejny obszar.
- Częsciowy odczyt z pliku natychmiast kończy pomyślnie całego read'a (oczywiście wykonanego częściowo)
- Dowolny inny problem (błąd czytania z pliku, błąd copy_to_user) zwraca błąd, potencjalnie modyfikując bufor użytkownika.

### ftruncate: zso_buffered_truncate

A) Wydłużanie:
    Tworzony jest nowy, wyzerowany wpis, rozciągający się między starym i nowym końcem pliku.    
B) Skracanie:
    1) Przegląda wpisy od tyłu i znajduje pierwszy, który należy w całości zostawić
    2) Jeżeli istnieją wpisy, które (częściowo) znajdują się poza nowym końcem pliku to są (przycinane) usuwane.

### fsync: zso_buffered_fsync

1) Wykonujemy do_sys_ftruncate, żeby uciąć fizyczny plik do buforowanego rozmiaru.
2) Wszystkie buforowane obszary po kolei zapisujemy na dysku oraz usuwamy z pamięci.

### (p)readv(2), (p)writev(2):

W do_iter_{read|write} widząc flagę O_BUFFERED_WRITE wymuszam skok do do_loop_readv_writev, gdzie wpinam się w istniejący kod zastępując wywołania do f_op->{read|write} przez zso_buffered_{read|write}.

### lseek SEEK_END, fstat

Korzystają z buforowanego file_size ¯\_(ツ)_/¯

## Inne

Dołączam (why not) callgraph wygenerowany przez:
egypt open.c.234r.expand file_table.c.234r.expand sync.c.234r.expand read_write.c.234r.expand zso.c.234r.expand | dot -Grankdir=LR -Tpdf -o callgraph.pdf
(Wymaga dodania w fs/Makefile: ccflags-y += -fdump-rtl-expand)
