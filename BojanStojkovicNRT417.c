#include<stdio.h>
#include<ctype.h>
#include<string.h>
#include<stdlib.h>
#include<conio.h>

#define MAX 80			//Za duzinu nizova

typedef enum{MEMORIJA,DATOTEKA,CITANJE,UPIS} UZROK;				// Deo koda za prikazivanje poruka o greskama.

char *poruke[]={	"\nProblem sa memorijom\n",                  
					"\nProblem sa datotekom\n",
					"\nProblem sa citanjem podataka\n",
					"\nProblem sa unosom podataka\n"};

int opcije();			//Funkvija koja ispisuje glavni meni, poziva se iz funkcije main i ne poziva druge funkcije, vraca odabranu stavku menia.

int odabir_sifre();		//Funkcija koja ispisuje postojece sifre i nudi korisniku da odabere koju zeli ili da doda novu, poziva se iz funkcije main i moze pozvati funkciju dodaj_sifru, vraca ceo broj koji pokazuje koja se sifra koristi.

void dodaj_sifru();		//Funkcija koja dodaje novu sifru u binarnu datoteku "sifre.bin", poziva se iz funkcije odabir_sifre i ne poziva druge funkcije.

int kreiraj_i_ili_otvori(int status);	//Funkcija koja otvara postojecu ili kreira novu datoteku nad kojom ce program raditi, poziva se iz funkcije main i ne poziva nijednu drugu funkciju, prihvata informaciju o tome da li treba otvoriti datoeku za sifrovanje ili desifrovanje ili treba kreirati novu i pripremiti je za sifrovanje, vraca informaciju o tome da li je za sifrovanje ili desifrovanje.

void info();				//Funkcija koja ispisuje INFO programa, poziva se iz funkcije main i ne poziva druge funkcije.

void nastavak();			//Funkcija koja trazi od korisnik da unese bilo sta da nastavi dalje, kada se koristi ova funkcija nije potrebno unositi ENTER nakon unosa, nakon ove funkcije cisti se prikaz i nastavlja se dalje. Poziva se iz svake funkcije sa sifrovanje ili desifrovanje i funkcije kreiraj_i_ili_otvori, ne poziva druge funkcije.

void prikaz_datoteke();		//Funkcija koja prikazuje datoteku cije ime korisnik unese, poziva se iz funkcije main i ne poziva druge funkcije.

void sifruj_cezar();		//Funkcija koja sifruje Cezarovom sifrom, poziva se iz main funkcije i poziva funkciju nastavak.

void desifruj_cezar();		//Funkcija koja desifruje Cezarovom sifrom, poziva se iz main funkcije i poziva funkciju nastavak.

void sifruj_desifruj_XOR(int provera);		//Funkcija koja siifruje ili desifruje ACII XOR sifrom, poziva se iz main funkcije i poziva funkciju nastavak, prihvata informaciu o tome da li treba da sifruje ili desifruje.

void sifruj_vizner();		//Funkcija koja sifruje Viznerovom sifrom, poziva se iz main funkcije i poziva funkciju nastavak.

void desifruj_vizner();		//Funkcija koja desifruje Viznerovom sifrom, poziva se iz main funkcije i poziva funkciju nastavak.

void sifruj_desifruj_KORISNIK(int status);		//Funkcija koja sifruje ili desifruje Korisnickom sifrom, poziva se iz main funkcije i poziva funkciju nastavak, prihvata informaciju o tome da li trena da sifruje ili desifruje.

void greska(UZROK);		//Funkcija koja daje informaciju o tome ukoliko dodje do neke greske prilikom rada sa nizovima ili datotekama, ukoliko dodje do greske to jest njenog izvrsavanja program ce zavrsiti sa radom, poziva se kod svake dodele ili realokacije niza , otvaranja datoteka ili upisa i citanja kod binarne datoteke, ne poziva druge funkcije.

void trenutni_prikaz(char *ime,FILE *datoteka);		//Funkcija koja ispisuje novonastalu datoteku nakon sifrovanja ili desifrovanja, poziva se iz svake funkcije za sifrovanje i desifrovanje i ne poziva druge funkcije, prihvata ime datoteke i pokazivac na tu datoteku.



struct sifre{						//struktura za sifre koje se upisuju u binarnu datoteku, sadrzi redni broj, ime i opis sifre.
	int rbr;
	char ime[MAX/2+1],opis[MAX+1];
};

FILE *trenutna=NULL;		//datoteka koju program sifruje/desifruje/ispisuje/kreira
char *ime_datoteke,*korisnicki_niz;		//ime trenutno otvorene datoteke i niz koji se sastoji od kljuca korisnicki definisaog sifranja
int povratak=0;		//koristi se da bi bio omogucen povratak na prethodnu opciju


/*Program prvobitno nije projektovan da ima mogucnost povratka nazad, opcija je dodata naknadno, zato je ubacena pomocna promeljiva "povratak"
 Promenljiva "povratak" sluzi da usmeri tok izvrsavanja programa na prethodni stepen izvrsavanja programa u odnosu na stepen u kom je zahtevan povratak,
 vodeci racuna o tome da se ponove opcije koje su dovele do tog stepena izvrsavanja. */


main()
{
	int opcija=0, sifruj_desifruj_flag=0,izbor=0,odabrana_sifra=0;		//opcija je opcija menia , sifruj_desifruj_flag odredjuje da li je zahtevano sifrovanje ili desifrovanje
	printf("Dobrodosli u program za sifrovanje i desifrovanje");		//izbor pamti izbor korisnika ukoliko dodje do povratka nazad, odabrana_sifra sluzi da se odabere funkcija kojom ce se sifrovati/desifrovati
	while(1)
	{
		if(povratak==1)							//ako je povratak usledio iz odabira sifre idi na odabir datoteke
		{
			switch(izbor)			//izbor korisnika koji je zapamcen
			{
			case 1: sifruj_desifruj_flag=(kreiraj_i_ili_otvori(1)); izbor=1; break;			//izbor se opet pamti ako korisnik pozeli opet da se vrati nazad i opet se unosi naziv datoteke
			case 2: sifruj_desifruj_flag=(kreiraj_i_ili_otvori(2)); izbor=2; break;
			case 3: sifruj_desifruj_flag=(kreiraj_i_ili_otvori(3)); izbor=3; break;
			}
			povratak=0;					//povratak se vraca na 0 da bi se omogucio normalan nastavak rada programa.
		}
		else if(povratak!=2)		//redovan tok izvrsavanja programa ukoliko prethodno nije bilo povratka
		{
			sifruj_desifruj_flag=0;
			switch(opcije())
			{
			case 1: sifruj_desifruj_flag=(kreiraj_i_ili_otvori(1)); izbor=1; break;		//
			case 2: sifruj_desifruj_flag=(kreiraj_i_ili_otvori(2)); izbor=2; break;		//	Bira se datoteka i pamti izbor opcije
			case 3: sifruj_desifruj_flag=(kreiraj_i_ili_otvori(3)); izbor=3; break;		//
			case 4: prikaz_datoteke(); break;
			case 5: info(); break;
			case 6: printf("\nOdabrali ste izlaz.\n"); exit(1);
			default: sifruj_desifruj_flag=0;
			}
		}
		if(sifruj_desifruj_flag==1)
		{
			povratak=0;							//obezbedjuje se normalan tok izvrsavanja programa, nastavak dalje
			odabrana_sifra=odabir_sifre();			//bira se sifra , moguce je da se povratak ovde postavi na 2 ako korisnik pozeli da se vrati nazad
			if(povratak!=2)
			{
			switch(odabrana_sifra)
				{											//sifrovanje odabranom sifrom
				case 1: sifruj_cezar(); break;
				case 2: sifruj_desifruj_XOR(1); break;		
				case 3: sifruj_vizner(); break;
				case 0: povratak=1; break;
				case 4: sifruj_desifruj_KORISNIK(1); break;
				}
			}
		}
		else if(sifruj_desifruj_flag==2)
		{
			povratak=0;							//obezbedjuje se normalan tok izvrsavanja programa, nastavak dalje
			odabrana_sifra=odabir_sifre();			//bira se sifra , moguce je da se povratak ovde postavi na 2 ako korisnik pozeli da se vrati nazad
			if(povratak!=2)
			{
				switch(odabrana_sifra)
				{											//desifrovanje odabranom sifrom
				case 1: desifruj_cezar(); break;
				case 2: sifruj_desifruj_XOR(2); break;
				case 3: desifruj_vizner(); break;
				case 0: povratak=1; break;
				case 4: sifruj_desifruj_KORISNIK(2); break;
				}
			}
		}
		system("cls");
	}
}

int opcije()												//Ispis i odabir opcije.
{
	int opcija=-1;
	printf("\n_________________________________________________________________");
	printf("\nOdaberite jednu od opcija, unesite redni broj opcije:\n");
	printf("_________________________________________________________________\n");
	printf("1. Sifrovanje postojece tekstualne datoteke.\n");
	printf("2. Desifrovanje postojece tekstualne datoteke.\n");
	printf("3. Kreiranje nove tekstualne datoteke i njeno sifrovanje.\n");
	printf("4. Prikaz datoteke\n");
	printf("5. INFO - nacin rada programa.\n");
	printf("6. IZLAZ\n");
	printf("_________________________________________________________________\n");
	printf("\nUnesite opciju: ");
	do
	{
		fflush(stdin);
		scanf("%d",&opcija);
		if(opcija<1||opcija>6)												//provera ispravnosti opcije
		{
			printf("Uneta je nepostojeca opcija, unesite ponovo: ");				
			opcija=-1;
		}
	}while(opcija<1);
	return(opcija);
}

int kreiraj_i_ili_otvori(int status)			//Otvara ili kreira datoteku, status govori da li je za sifrovanje ili desifrovanje.
{
	char karakter,*puno_ime_datoteke;		//karakter-unos karaktera u kreiranu datoteku, puno_ime_datoteke - na uneto ime datoteke program automatski dodaje ".txt".
	printf("\nUkoliko zelite da se vratite nazad unesite znak / umesto imena datoteke\n");
	do{
		ime_datoteke=(char *)malloc(MAX+1);
		if(ime_datoteke==NULL) greska(MEMORIJA);
		if(status==2)									//Ako je otvaranje datoteke za desifrovanje podsetnik korisnika da treba da doda "_sifrovano".
		{					
			printf("\nPODSETNIK ! Da biste desifrovali vec postojecu datoteku morate dodati sufiks \"_sifrovano\" u suprotnom desifrovacete originalnu datoteku i rezultat nece biti validan.\n");
		}
		printf("\nUnesite ime datoteke: ");
		fflush(stdin);
		gets(ime_datoteke);
		if(strcmp(ime_datoteke,"/")==0)		//Ukoliko je unet znak / povratak unazad, u ovom slucaju na pocetni meni.
		{
			free(ime_datoteke);
			return 0;
			break;
		}
		else
		{
			ime_datoteke=(char *)realloc(ime_datoteke,strlen(ime_datoteke)+1);				
			if(ime_datoteke==NULL) greska(MEMORIJA);
			puno_ime_datoteke=(char *)malloc(strlen(ime_datoteke)+strlen(".txt")+1);		//Na uneto ime datoteke dodaje se ".txt".
			if(puno_ime_datoteke==NULL) greska(MEMORIJA);
			strcpy(puno_ime_datoteke,ime_datoteke);
			strcat(puno_ime_datoteke,".txt");
			if((trenutna=fopen(puno_ime_datoteke,"r"))!=NULL)		//Ako je ispunjen ovaj uslov znaci da je uneta datoteka koja vec postoji.
			{
				if(status==1)
				{
					printf("\nUspesno ste otvorili datoteku %s\nDatoteka je spremna za sifrovanje",puno_ime_datoteke);	//Ako je zahtevano sifrovanje postojece datoteke uspesno je otvorena za sifrovanje.
					free(puno_ime_datoteke);
					nastavak();
					return(1);
					break;
				}
				else if(status==2)
				{
					printf("\nUspesno ste otvorili datoteku %s\nDatoteka je spremna za desifrovanje",puno_ime_datoteke);	//Ako je zahtevano desifrovanje datoteke uspesno je otvorena za desifrovanje.
					free(puno_ime_datoteke);
					nastavak();
					return(2);
					break;
				}
				else if(status==3)
				{
					printf("\nVec postoji datoteka sa ovim imenom\n");		//Ako se zahteva kreiranje nove datoteke, petlja ce se ponoviti i zahtevace se ponovo unos imena zato sto vec postoji datoteka sa tim imenom.
					fclose(trenutna);
					free(ime_datoteke);
					free(puno_ime_datoteke);
				}
			}
			else if(status==3)
			{																//Ako datoteka ne postoji, a trazi se kreiranje, datoteka je kreirana i spremna za upis.
					
				trenutna=fopen(puno_ime_datoteke,"w+");
				if(trenutna==NULL) greska(DATOTEKA);
				printf("\nUspesno se kerirali datoteku.\n");
				break;
			}
			else													//Ako datoteka ne postoji a zahteva se sifrovaje postojece ili desifrovanje, ponavlja se petlja i ponovo se trazi unos imena datoteke.
			{
				printf("\nUneli ste nepostojecu datoteku\n");
			}
		}
	}while(1);
	
	//Odavde do kraja funkcije se izvrsava samo ako je status 3 odnosno ako se trazi kreiranje datoteke, ako su zahtevi drugaciji return je bio pre ovog dela koda.

	printf("Upisite tekst u datoteku,za kraj unosa unesite * a potom ENTER.\n");
	while((karakter=getchar())!='*')
	{												//Unos karaktera u novu datoteku sve dok se ne unese *.
		fputc(karakter,trenutna);
	}
	printf("\nSadrzaj je upisan u datoteku");
	rewind(trenutna);								//Premotavanje datoteke na pocetak kako bi bilo omoguceno citanje i njeno dalje sifrovanje.
	free(puno_ime_datoteke);
	nastavak();
	return(1);
}

int odabir_sifre()							//Kreiranje datoteke sa siframa i odabir sifre
{
	FILE *fptr;
	struct sifre *spisak;			//spisak - niz struktura sifri koje se upisuju ili citaju iz datoteke
	int i,brojsifri=3,odabrano=-1;		//odabrano - odabrana sifra
	char *unos,nazad;				//unos - unos korisnika kada bira sifre, nazad - unos korisnika ako zeli da se vrati nazad
	system("cls");
	if((fptr=fopen("sifre.bin","rb"))==NULL)		//Ako je NULL ne postoji, znaci treba kreirati datoteku sa siframa.
	{												//Izvrsava se samo prvi put dok se ne unesu standardne sifre sa kojima program radi.
		fptr=fopen("sifre.bin","wb");				//Programer kreira datoteku sa siframa tako da kada koriisnik koristi program ovaj deo se ne izvrsava nikada.
		if(fptr==NULL) greska(DATOTEKA);
		if((fwrite(&brojsifri,sizeof(int),1,fptr))!=1) greska(UPIS);	//Prvi podatak u datoteci je broj sifri ovde je to 3, kasnije ako korisnici kreiraju svoje sifre taj broj se menja.
		spisak=(struct sifre*)malloc(brojsifri*sizeof(struct sifre));
		if(spisak==NULL) greska(MEMORIJA);
		for(i=0;i<brojsifri;i++)
		{															//Unos sifri
			fflush(stdin);
			printf("\nUneti redni broj sifre: ");
			scanf("%d",&spisak[i].rbr);
			printf("Uneti ime sifre: ");
			fflush(stdin);
			gets(spisak[i].ime);
			printf("Uneti opis sifre: ");
			fflush(stdin);
			gets(spisak[i].opis);
			if(fwrite(&spisak[i],sizeof(struct sifre),1,fptr)!=1) greska(UPIS);
		}
		printf("\nKreirana je datoteka sa siframa\n");
		free(spisak);
		fclose(fptr);
	}
	else																			//Korisnik dobija program koji se izvrsava odavde
	{
		if(fread(&brojsifri,sizeof(int),1,fptr)!=1) greska(CITANJE);
		spisak=(struct sifre*)malloc(brojsifri*sizeof(struct sifre));
		if(spisak==NULL) greska(MEMORIJA);
		for(i=0;i<brojsifri;i++)
		{																				//Cita se broj sifri i ispisuje se sve sifre
			if(fread(&spisak[i],sizeof(struct sifre),1,fptr)!=1) greska(CITANJE);
			printf("\n%d. %s\nOpis: %s ",spisak[i].rbr,spisak[i].ime,spisak[i].opis);
		}
		fclose(fptr);
		printf("\n\nSifre sa rednim brojem vecim od 3 su korisnicke sifre, one zamenjuju znak iz opisa sledecim i obrnuto.\n");
		printf("\Primer: Opis = abcd12, a postaje b , b postaje a , c postaje d , d postaje c, 1 postaje 2, 2 postaje 1.");
		printf("\n\nUnesite / ako zelite da se vratite nazad.\n");
		printf("\nUnesite redni broj sifre ili + ako zelite da kreirate novu sifru: ");
	}
	do{																//Korisnik bira sifru
		unos=(char*)malloc(MAX/2+1);
		if(unos==NULL) greska(MEMORIJA);						
		fflush(stdin);
		gets(unos);
		if(strcmp(unos,"/")==0)						//Korisnik je odabrao da se vrati unazad, u ovom slucaju na unos imena datoteke
		{
			free(spisak);
			fclose(trenutna);
			free(ime_datoteke);
			fflush(stdin);
			free(unos);
			return(0);
			break;
		}
		else if(strcmp(unos,"+")==0)			//Korisnik je odabrao da unese kreira novu sifru
		{
			odabrano=0;
			free(unos);
			break;
		}
		else
		{
			if(atoi(unos))								//Provera unosa
			{
				odabrano=atoi(unos);
				if(odabrano<0||odabrano>brojsifri)
				{
					printf("Uneta je nepostojeca opcija, unesite ponovo: ");
					odabrano=-1;
				}
			}
			else
			{
				printf("Uneta je nepostojeca opcija, unesite ponovo: ");
			}
			free(unos);
		}
	}while(odabrano<0);				//Nakon zavrsetka petlje korisnik je odabrao sifru ili zeli da kreira novu ili da se vrati unazad.
	system("cls");						
	if(odabrano==0)				
	{							//Ako je odabrano kreiranje nove sifre
		dodaj_sifru();				
		free(spisak);
		return(4);
	}
	else 
	{
		for(i=0;i<brojsifri;i++)
		{
			if(odabrano==spisak[i].rbr)					
			{											
				printf("\nOdabrali ste:\n");														//Ispis odabrane sifre.
				printf("\n%d. %s\nOpis: %s \n",spisak[i].rbr,spisak[i].ime,spisak[i].opis);
				printf("\nUnesite / ako zelite da se vratite nazad ili bilo sta drugo da nastavite dalje\n"); //Mogucnos povratka unazad.
				fflush(stdin);
				nazad = getchar();
				if(nazad=='/')				//Odabran povratak.
				{
					povratak=2;
					return(odabrano);     //Nije bitno sta ce vratiti jer je izabran povratak nazad tako da se sifrovanje/desifrovanje nece izvrsiti,ide se unazad to jest ponovo se bira sifra.
				}
				if(odabrano>3)
				{																		//Ako je odabrana neka od korisnickih sifri pamcenje njenog kljuca u niz radi koriscenja u funkciji sifruj_desifruj_korisnik
					korisnicki_niz=(char *)malloc(strlen(spisak[i].opis)+1);
					if(korisnicki_niz==NULL) greska(MEMORIJA);
					strcpy(korisnicki_niz,spisak[i].opis);
					free(spisak);
					return(4);
					break;
				}
				else					//Ako je odabrana neka od tri standardne sifre vrati njen broj
				{
					free(spisak);
					return(odabrano);
					break;
				}
			}
		}
	}
}

void dodaj_sifru()									//Dodavanje nove sifre
{
	int brojsifri;
	struct sifre novasifra;
	FILE *fptr;
	system("cls");															
	printf("\n\nDodajte sifru");
	printf("\n\nUnesite / ako zelite da se vratite nazad.\n");
	printf("\nUnesite naziv nove sifre\n");										//Funkcija odma trazi unos imena ukoliko se unese / vrsi se povratak nazad, to jest ponovo se bira sifra
	fflush(stdin);
	gets(novasifra.ime);
	if(strcmp(novasifra.ime,"/")==0)
	{
		povratak=2;
	}
	else
	{
		fptr=fopen("sifre.bin","rb+");											//Cita se broj sifri sa pocetka kako bi se redni broj nove sifre automatski generisao
		if(fptr==NULL) greska(DATOTEKA);
		if(fread(&brojsifri,sizeof(int),1,fptr)!=1) greska(CITANJE);
		novasifra.rbr=brojsifri+1;											//Redni broj sifre ujedno i novi broj sifri
		fseek(fptr,-sizeof(int),SEEK_CUR);
		if(fwrite(&novasifra.rbr,sizeof(int),1,fptr)!=1) greska(CITANJE);			//Novi broj sifri se upisuje u datoteku
		printf("\nUnesite opis sifre, ovo ce predstavljati kljuc kojim cete sifrovati to jest desifrovati");
		printf("\nPreporucljivo je uneti znakove a-z , A-Z , 0-9");
		printf("\nUnosite znakove redom bez razmaka,bitno je da broj znakova bude paran i da se znakovi ne ponavljaju\n");
		printf("Krsenje ovih pravila dovesce do neispravnog sifrovanja/desifrovanja\n");
		fflush(stdin);
		gets(novasifra.opis);
		fclose(fptr);
		korisnicki_niz=(char *)malloc(strlen(novasifra.opis)+1);	//Nakon unosa nove sifre odma se nastavlja sa sifrovanjem datoteke novom sifrom,
		if(korisnicki_niz==NULL) greska(MEMORIJA);					//kljuc se smesta u korisnciki niz koji ce se koristiti u funkciji sifruj_desifruj_korisnik
		strcpy(korisnicki_niz,novasifra.opis);
		fptr=fopen("sifre.bin","ab");
		if(fptr==NULL) greska(DATOTEKA);
		if(fwrite(&novasifra,sizeof(struct sifre),1,fptr)!=1) greska(UPIS);		//Upis kompletne strukture novasifra u datoteku
		printf("\n");
		fclose(fptr);
		printf("Ovo je vasa sifra: \n");
		printf("\n%d. %s\nOpis: %s ",novasifra.rbr,novasifra.ime,novasifra.opis);
	}
}

void sifruj_cezar()					//Sifrovanje Cezarovom sifrom
{
	FILE *sifrovano;				//sifrovano-pokazivac na novu datoteku koja ce nastati sifrovanjem/desifrovanjem trenutne OVO JE ISTO ZA SVE SIFRE KOJE SIFRUJU/DESIFRUJU.
	char karakter,*novo_ime;		//karakter-u ovu promenljivu se smesta karakter iz trenutne datoteke menja se i upisuje u novu, novo_ime-naziv nove datoteke OVO JE ISTO ZA SVE FUNKCIJE KOJE SIFRUJU/DESIFRUJU.
	system("cls");					
	novo_ime=(char *)malloc(strlen(ime_datoteke)+strlen("_sifrovano.txt")+1);
	if(novo_ime==NULL) greska(MEMORIJA);
	strcpy(novo_ime,ime_datoteke);
	strcat(novo_ime,"_sifrovano.txt");			//Automatsko dodavanje sufiksa "_sifrovano" OVO JE ISTO ZA SVAKU FUNKCIJU KOJA SIFRUJE/DESIFRUJ ako desifuje sufiks je "_desifrovano".
	sifrovano=fopen(novo_ime,"w+");
	if(sifrovano==NULL) greska(DATOTEKA);
	while((karakter=fgetc(trenutna))!=EOF)
	{
		if((karakter>='a'&&karakter<'x')||(karakter>='A'&&karakter<'Z'))				//Ako je slovo od a-z ili A-Z dodaje se 3.
		{
			karakter+=3;
		}
		else if(karakter=='x'||karakter=='X'||karakter=='y'||karakter=='Y'||karakter=='z'||karakter=='Z')	//Ako je slovo x,y,z ili X,Y,Z oduzima se 23.
		{																									
			karakter-=23;
		}
		fputc(karakter,sifrovano);
	}
	printf("\nUspesno sifrovano\n");
	rewind(sifrovano);						//Premotavanje da bi se procitala novonastala datoteka	ISTO ZA SVAKU FUNKCIJU KOJA SIFRUJE/DESIFRUJE
	trenutni_prikaz(novo_ime,sifrovano);		//Poziv funkcije koja ce prikazati novonastalu datoteku  ISTO ZA SVAKU FUNKCIJU KOJA SIFRUJE/DESIFRUJE
	fclose(trenutna);
	fclose(sifrovano);
	free(novo_ime);
	nastavak();
}

void desifruj_cezar()
{
	FILE *desifrovano;
	char karakter,*novo_ime;
	system("cls");
	novo_ime=(char *)malloc(strlen(ime_datoteke)+strlen("_desifrovano.txt")+1);
	if(novo_ime==NULL) greska(MEMORIJA);
	strcpy(novo_ime,ime_datoteke);
	strcat(novo_ime,"_desifrovano.txt");
	desifrovano=fopen(novo_ime,"w+");
	if(desifrovano==NULL) greska(DATOTEKA);
	while((karakter=fgetc(trenutna))!=EOF)
	{
		if((karakter>='d'&&karakter<='z')||(karakter>='D'&&karakter<='Z'))
		{
			karakter-=3;
		}
		else if(karakter=='a'||karakter=='A'||karakter=='b'||karakter=='B'||karakter=='c'||karakter=='C')
		{
			karakter+=23;
		}
		fputc(karakter,desifrovano);
	}
	printf("\nUspesno desifrovano\n");
	rewind(desifrovano);
	trenutni_prikaz(novo_ime,desifrovano);
	fclose(desifrovano);
	fclose(trenutna);
	free(novo_ime);
	nastavak();
}

void sifruj_desifruj_XOR(int provera)
{
	FILE *sifruj_desifruj;
	char karakter,*novo_ime,*unos;
	int kljuc=1001;
	system("cls");
	printf("\n\nUnesite / ako zelite da se vratite nazad.\n");
	printf("\nUnesite kljuc kojim zelite da sifrujete/desifrujete (od 1 do 10): ");
	unos=(char*)malloc(MAX/2+1);
	do
	{
		fflush(stdin);
		gets(unos);
		if(strcmp(unos,"/")==0)				//Ako je uneto / povratak unazad, to jest ponovo se bira sifra.
		{
			povratak=2;
			free(unos);
			break;
		}
		kljuc=atoi(unos);						//Provera kljuca
		if(kljuc<1||kljuc>10)
		{
			printf("Uneta je nepostojeca opcija, unesite ponovo: ");
		}
		else
		{
			free(unos);
			break;
		}
	}while(1);
	if(povratak!=2)			//Ako je odabran povrataka nadalje se nista nece izvrsiti
	{
		if(provera==1)
		{
			novo_ime=(char *)malloc(strlen(ime_datoteke)+strlen("_sifrovano.txt")+1);
			if(novo_ime==NULL) greska(MEMORIJA);
			strcpy(novo_ime,ime_datoteke);
			strcat(novo_ime,"_sifrovano.txt");
		}
		else
		{
			novo_ime=(char *)malloc(strlen(ime_datoteke)+strlen("_desifrovano.txt")+1);
			if(novo_ime==NULL) greska(MEMORIJA);
			strcpy(novo_ime,ime_datoteke);
			strcat(novo_ime,"_desifrovano.txt");
		}
		sifruj_desifruj=fopen(novo_ime,"w+");
		if(sifruj_desifruj==NULL) greska(DATOTEKA);
		printf("\n\n%d\n\n",kljuc);
		while((karakter=fgetc(trenutna))!=EOF)
		{
			if(karakter!=' '||karakter!='\n'||karakter!='\t')
			{
				karakter^=kljuc;									//Sifrovanje/Desifrovanje
			}
			fputc(karakter,sifruj_desifruj);
		}
	
		if(provera==1)
		{
			printf("\nUspesno sifrovano\n");
		}
		else
		{
			printf("\nUspesno desifrovano\n");
		}
		rewind(sifruj_desifruj);
		trenutni_prikaz(novo_ime,sifruj_desifruj);
		fclose(sifruj_desifruj);
		fclose(trenutna);
		free(novo_ime);
		nastavak();
	}
}

void sifruj_vizner()
{
	FILE *sifrovano;
	char karakter,*novo_ime,*kljuc;
	int i=0;
	system("cls");
	printf("\n\nUnesite / ako zelite da se vratite nazad.\n");
	printf("\nUnesite kljuc kojim zelite da sifrujete, kljuc moze sadrzati iskljucivo slova,i ne sme biti duzi od 30 karaktera,\n u suprotnom sifrovanje nece biti ispravno : ");
	kljuc=(char*)malloc(MAX+1);
	scanf("%s",kljuc);
	kljuc=(char *)realloc(kljuc,strlen(kljuc)+1);
	if(kljuc==NULL) greska(MEMORIJA);
	if(strcmp(kljuc,"/")==0)				//Ako je za kljuc uneto / odabran je povratak, vracanje unazad to jest ponovo se bira sifra.
	{
		free(kljuc);
		povratak=2;
	}
	if(povratak!=2)
	{
		novo_ime=(char *)malloc(strlen(ime_datoteke)+strlen("_sifrovano.txt")+1);
		if(novo_ime==NULL) greska(MEMORIJA);
		strcpy(novo_ime,ime_datoteke);
		strcat(novo_ime,"_sifrovano.txt");
		sifrovano=fopen(novo_ime,"w+");
		if(sifrovano==NULL) greska(DATOTEKA);
		while(1)
		{
			karakter=fgetc(trenutna);
			if(karakter==EOF) break;
			if(kljuc[i]=='\0') i=0;					//Ako se prodju sva slova iz kljuca vrati se na pocetak kljuca.
			if(karakter>='a'&&karakter<='z')
			{
				kljuc[i]=tolower(kljuc[i]);				//Ako je karakter malo slovo obezbedi da kljuc isto bude malo slovo.
				if((karakter+kljuc[i]-2*97)<26)						
				{											//Ako je sabiranjem slova novonastalo slovo u opsegu 0-25 tj nije preslo opseg slova.
					karakter=(karakter+kljuc[i]-97);		//Saberi i vrati u opseg ASCII brojeva za slova.
					fputc(karakter,sifrovano);
				}
				else										//Ako je slovo "preteklo" tj sabiranjem se dobije veci broj od 26.
				{
					karakter=(karakter+kljuc[i]-26-97);		//Oduzmi visak i vrati u opseg ASCII brojeva za slovo.
					fputc(karakter,sifrovano);
				}
				i++;
			}
			else if(karakter>='A'&&karakter<='Z')
			{
				kljuc[i]=toupper(kljuc[i]);					////Ako je karakter veliko slovo obezbedi da kljuc isto bude veliko slovo.
				if((karakter+kljuc[i]-2*65)<26)
				{
					karakter=(karakter+kljuc[i]-65);								//Isto kao za mala slova samo je pomeraj 65.
					fputc(karakter,sifrovano);
				}
				else
				{
					karakter=(karakter+kljuc[i]-26-65);
					fputc(karakter,sifrovano);
				}
				i++;
			}
			else
			{
				fputc(karakter,sifrovano);
			}
		}
		printf("\nUspesno sifrovano\n");
		rewind(sifrovano);
		trenutni_prikaz(novo_ime,sifrovano);
		fclose(sifrovano);
		fclose(trenutna);
		free(novo_ime);
		free(kljuc);
		nastavak();
	}

}

void desifruj_vizner()
{
	FILE *desifrovano;
	char karakter,*novo_ime,*kljuc;
	int i=0;
	system("cls");
	printf("\n\nUnesite / ako zelite da se vratite nazad.\n");
	printf("\nUnesite kljuc kojim zelite da desifrujete, kljuc moze sadrzati iskljucivo slova,i ne sme biti duzi od 30 karaktera, u suprotnom desifrovanje nece biti ispravno : ");
	kljuc=(char*)malloc(MAX+1);
	scanf("%s",kljuc);
	kljuc=(char *)realloc(kljuc,strlen(kljuc)+1);
	if(kljuc==NULL) greska(MEMORIJA);
	if(strcmp(kljuc,"/")==0)						//Ako je za kljuc uneto / odabran je povratak, vracanje unazad to jest ponovo se bira sifra.
	{
		free(kljuc);
		povratak=2;
	}
	if(povratak!=2)
	{
		novo_ime=(char *)malloc(strlen(ime_datoteke)+strlen("_desifrovano.txt")+1);
		if(novo_ime==NULL) greska(MEMORIJA);
		strcpy(novo_ime,ime_datoteke);
		strcat(novo_ime,"_desifrovano.txt");
		desifrovano=fopen(novo_ime,"w+");
		if(desifrovano==NULL) greska(DATOTEKA);
		while(1)
		{
			karakter=fgetc(trenutna);
			if(karakter==EOF) break;
			if(kljuc[i]=='\0') i=0;								//Ako se prodju sva slova iz kljuca vrati se na pocetak kljuca.
			if(karakter>='a'&&karakter<='z')
			{
				kljuc[i]=tolower(kljuc[i]);
				if((karakter-kljuc[i])>=0)							//Ako se oduzimanjem kljuca od karaktera dobije broj veci od 0.
				{
					karakter=karakter-kljuc[i]+97;			//Oduzmi kljuc od karaktera i vrati ga u opseg ASCII brojeva za slovo.
					fputc(karakter,desifrovano);
				}
				else											//Ako se oduzimanjem kljuca od karaktera dobije manji broj od 0.
				{
					karakter=(karakter-kljuc[i]+26+97);			//Oduzmi kljuc od karaktera dodaj mu 26 i vrati ga u opseg ASCII brojeva za slovo.
					fputc(karakter,desifrovano);
				}
				i++;
			}
			else if(karakter>='A'&&karakter<='Z')
			{
				kljuc[i]=toupper(kljuc[i]);
				if((karakter-kljuc[i])>=0)								//Isto kao za malo slovo samo je pomeraj 65.
				{
					karakter=karakter-kljuc[i]+65;
					fputc(karakter,desifrovano);
				}
				else
				{
					karakter=(karakter-kljuc[i]+26+65);
					fputc(karakter,desifrovano);
				}
				i++;
			}
			else
			{
				fputc(karakter,desifrovano);
			}		
		}
		printf("\nUspesno desifrovano\n");
		rewind(desifrovano);
		trenutni_prikaz(novo_ime,desifrovano);
		fclose(trenutna);
		fclose(desifrovano);
		free(novo_ime);
		free(kljuc);
		nastavak();
	}
}

void sifruj_desifruj_KORISNIK(int status)
{
	FILE *sifruj_desifruj;
	char karakter,*novo_ime;
	int i=0,provera=0;				//provera-pomocna promenljiva koja sluzi da se karakter ne unose dva puta
	if(status==1)
	{
		novo_ime=(char *)malloc(strlen(ime_datoteke)+strlen("_sifrovano.txt")+1);
		if(novo_ime==NULL) greska(MEMORIJA);
		strcpy(novo_ime,ime_datoteke);
		strcat(novo_ime,"_sifrovano.txt");
	}
	else
	{
		novo_ime=(char *)malloc(strlen(ime_datoteke)+strlen("_desifrovano.txt")+1);
		if(novo_ime==NULL) greska(MEMORIJA);
		strcpy(novo_ime,ime_datoteke);
		strcat(novo_ime,"_desifrovano.txt");
	}
	sifruj_desifruj=fopen(novo_ime,"w+");
	if(sifruj_desifruj==NULL) greska(DATOTEKA);
	while(1)
	{
		karakter=fgetc(trenutna);
		if(karakter==EOF) break;
		for(i=0;i<strlen(korisnicki_niz);i++)     //Poredjenje karaktera sa svakim clanom niza da vidimo da li treba da se zameni
		{
			if(karakter==korisnicki_niz[i])		//Ako je pronadjen
			{
				if(i%2==0)									//Ako je karakter jednak sa claom niza koji je na parnoj poziciji  zameni ga sledecim.
				{
					karakter=korisnicki_niz[i+1];
				}
				else{										//Ako je karakter jednak sa claom niza koji je na neparnoj poziciji  zameni ga prethodnim.
					karakter=korisnicki_niz[i-1];
				}
				fputc(karakter,sifruj_desifruj);	//Upis izmenjenog karaktera.
				provera=1;								//Postavlja se provera na 1 da se karakter ne bi upisao 2 puta.
				break;
			}
		}
		if(provera==0)								//Ako je provera 0 znaci karakter ne treba da se menja vec se samo upisuje u novu datoteku.
		{
			fputc(karakter,sifruj_desifruj);
		}
		provera=0;
	}
	if(status==1)
	{
		printf("\nUspesno sifrovano\n");
	}
	else
	{
		printf("\nUspesno desifrovano\n");
	}
	rewind(sifruj_desifruj);
	trenutni_prikaz(novo_ime,sifruj_desifruj);
	fclose(sifruj_desifruj);
	fclose(trenutna);
	free(korisnicki_niz);
	free(novo_ime);
	nastavak();
}

void prikaz_datoteke()				//Prikaz datoteke
{
	char karakter,*ime;
	int izlaz=0;				//Omogucava izlaz iz opcije
	system("cls");
	printf("\nUnesite / ako zelite da se vratite nazad\n");			//Izlaz iz prikaza datoteke ako se unese /, povratak na pocetni meni
	printf("\nUnesite ime datoteke koju zelite da procitate\n");
	do{
		ime=(char *)malloc(MAX+1);
		if(ime==NULL) greska(MEMORIJA);
		fflush(stdin);
		gets(ime);
		if(strcmp(ime,"/")==0)
		{
			izlaz=1;
			free(ime);
			break;
		}
		ime=(char *)realloc(ime,strlen(ime)+strlen(".txt")+1);
		if(ime==NULL) greska(MEMORIJA);
		strcat(ime,".txt");
		trenutna=fopen(ime,"r");
		if(trenutna==NULL)															//Provera da li datoteka postoji ako ne, ponovo unesi
		{
			printf("\nUneli ste nepostojecu datoteku, unesite ime opet\n");
			free(ime);
		}
		else break;
	}while(1);
	if(izlaz==0)
	{
		while((karakter=fgetc(trenutna))!=EOF)
		{
			putchar(karakter);
		}
		printf("\n\nZavrsen ispis datoteke\n");
		fclose(trenutna);
		free(ime);
		nastavak();
	}
}

void info()
{

	FILE *fptr;
	char karakter;
	system("cls");
	fptr=fopen("info.txt","r");
	if(fptr==NULL) greska(DATOTEKA);
	while((karakter=fgetc(fptr))!=EOF)
	{
	putchar(karakter);
	}
	nastavak();

}
void nastavak()
{
	printf("\n\nUnesite bilo sta da nastavite dalje\n");
	fflush(stdin);
	getch();
}
void trenutni_prikaz(char *ime,FILE *datoteka)
{
	char karakter;
	printf("\nNovonastala datoteka: %s izgleda ovako: \n\n",ime);
	while((karakter=fgetc(datoteka))!=EOF)
	{
		putchar(karakter);
	}	
}

void greska(UZROK status)
{
	fprintf(stderr,"%s",poruke[status]);
	exit(1);
}