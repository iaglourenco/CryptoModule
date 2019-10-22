/**
 * @file   testecrypto.c
 * @author Adriano Munin, Fabio Irokawa, Iago Lourenço, Lucas Coutinho
 * @date   Setembro 2019
 * @version 0.1
 * @brief Programa que enviara requisiçoes ao LKM de criptografia
*/
#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>
#include<ctype.h>

void converteHexa(char *string, char *hexa);
void insereOpcInicio(char *entrada, char *saida, char opc);
int converteASCII(char *string, char ascii[]);

int main(int argc, char *argv[]){

   uid_t uid=getuid();
   int option=-99;
   int ret,crypto;
   char *operacao = argv[1];
   char *msgHexa;
   char *temp;
   static char *recebido;
   static char recebidoHash[41];
   int flagHexa=0;

   if(argc==1) operacao = "none";
   

   
   if(strcmp(operacao,"c")==0) {
      if(argc<3){printf("A opcao requer argumentos -- '%s'\n",operacao);goto syntax;}
      option=1;
   }
   if(strcmp(operacao,"d")==0) {
      if(argc<3){printf("A opcao requer argumentos -- '%s'\n",operacao);goto syntax;}
      option=2;
   }
   
   if(strcmp(operacao,"h")==0) {
      if(argc<3){printf("A opcao requer argumentos -- '%s'\n",operacao);goto syntax;}
       option=3;
   }
   if(strcmp(operacao,"-h")==0){
      option=0;
      goto help;
   }
   if(option >=1 && option <=3){
      if(uid!=0){
         printf(".:CryptoDev:. precisa ser executado como root...\n");
         printf("Faca login como root (su root) ou tente 'sudo ./crypto' ...\n");
         return 0;

      }else{
      crypto = open("/dev/crypto",O_RDWR);
         if(crypto < 0){
            perror("Falha ao acessar dispositivo...");
            return errno;
         }
      }
   }
   

   if(argv[3] !=NULL){

      if(strcmp(argv[3],"--hexa")==0)
      {
         for(int i = 0; i < strlen(argv[2]); i++)
         {
            if(((argv[2][i] >= 48 && argv[2][i] <= 57) || (argv[2][i] >= 65 && argv[2][i] <= 70) || (argv[2][i] >= 97 && argv[2][i] <= 102)) && ((strlen(argv[2]) % 2) == 0))
            {
               flagHexa=1;
            }
            else
            {
               printf("Digite uma entrada em hexadecimal valida!\n");
               goto syntax;
            }
         }
      }
      else if(strcmp(argv[3],"--hexa")==0 && strcmp(operacao,"d")){

         printf("A entrada em hexa somente e permitida na criptografia\n");
         goto syntax;

      }else{
         printf("Opcao '%s' desconhecida... \n",argv[3]);
         goto syntax;
      }
   }

   if(flagHexa==1)
      msgHexa=malloc(strlen(argv[2])+1);   
   else
      msgHexa=malloc(strlen(argv[2])*2+1);
   
   if(!msgHexa){
      perror("Falha ao alocar memoria...");
      return errno;
   }

   if(flagHexa==1)
      temp=malloc(strlen(argv[2]));
   else
      temp=malloc(strlen(argv[2])*2);
   
   if(!temp){
      perror("Falha ao alocar memoria...");
      return errno;
   }
   recebido=malloc(strlen(argv[2])*16);
   if(!recebido){
      perror("Falha ao alocar memoria...");
      return errno;
   }


   switch (option)
   {
      case 1:
         printf("--:Criptografia:--\n");

         if(flagHexa==0){
            converteHexa(argv[2], temp);
         }
         else{
            strcpy(temp,argv[2]);
         }


         insereOpcInicio(temp,msgHexa,'c');
         
         ret = write(crypto,msgHexa,strlen(msgHexa));
         if(ret < 0){
            perror("Falha ao enviar dado ao dispositivo...");
            return errno;
         }
         
         ret = read(crypto,recebido,strlen(recebido));
         if(ret < 0){
            perror("Falha ao ler dado do dispositivo...");
            return errno;
         }
         printf("\nDado enviado: %s",msgHexa+1);
         printf("\nDado criptografado: %s\n",recebido);   
      break;

      case 2:
         printf("--<Descriptografia>--\n");
          
         insereOpcInicio(argv[2], msgHexa, 'd');
         
         ret = write(crypto,msgHexa,strlen(msgHexa));
         if(ret < 0){
	    if (ret == -1){
            	perror("Nao e possivel descriptografar esta mensagem, tente novamente");
            	return errno;
         	}
            perror("Falha ao enviar dado ao dispositivo...");
            return errno;
         }

         ret = read(crypto,recebido,strlen(recebido));
         if(ret < 0){
            perror("Falha ao ler dado do dispositivo...");
            return errno;
         }

 	 temp = malloc((strlen(recebido))/2);
	 
	
         printf("\nDado enviado: %s",msgHexa+1);
         printf("\nDado descriptografado: %s",recebido);
         if(converteASCII(recebido, temp))
	         printf("\nDado descriptografado ASCII: %s\n",temp);
         else
            printf("\nNao e possivel imprimir em ASCII, existe algum caractere nao imprimivel\n");
              

      break;

      case 3:
         printf("-#-Gerar Hash-#-\n");


         if(flagHexa==0){
            converteHexa(argv[2], temp);
         }
         else{
            strcpy(temp,argv[2]);
         }

         insereOpcInicio(temp,msgHexa,'h');
         

         ret = write(crypto,msgHexa,strlen(msgHexa));
         if(ret < 0){
            perror("Falha ao enviar dado ao dispositivo...");
            return errno;
         }
         ret = read(crypto,recebidoHash,40);
         if(ret < 0){
            perror("Falha ao ler dado do dispositivo...");
            return errno;
         }
         printf("\nDado enviado: %s",msgHexa+1);
         printf("\nHash: %s\n",recebidoHash); 

      break;
   case 0:
   help:
      printf(".:CryptoDev:. - Desenvolvido por Adriano, Fabio, Iago e Lucas\n");
      printf("Faz operaçoes de criptografia usando um LKM\n");
      printf("Como usar: ./crypto [OPERACAO] [DADO] [--hexa]\n------\n");
      printf("OPERACOES \n\t c - Criptografar\n\t d - Descriptografar\n\t h - Gerar Hash\n\t-h - Esta tela de ajuda\n\n");
      printf("DADO\n\t\n\tc,h - No minimo 1 caracter\n\td - Mensagem a ser descriptografada\n\n");
      printf("A opcao '--hexa' apos o dado, fara com que o dado seja tratado como hexadecimal,\nsendo permitida somente na criptografia e no hash!\n");
      break;
   default:
syntax:
      printf("Sintaxe invalida!!\n\n Exemplo: ./crypto [cdh] [DADO] [OPCOES]... Tente './crypto -h' para ajuda.\n");
      return 0;
      break;
   }   
   return 0;
}



void converteHexa(char *string, char hexa[]){
   int tam = strlen(string);
   int i;
   for(i = 0; i < tam; i++){        
      sprintf(hexa+i*2,"%02x", string[i]);
   }
   sprintf(hexa+i*2+1,"%c",'\0'); 
}

void insereOpcInicio(char entrada[], char saida[], char opc){
   int tam, i;
   tam = strlen(entrada);

   saida[0]= opc;
   for(i = 0; i < tam; i++){
      saida[i+1] = entrada[i];
   }
   saida[i+1]='\0';   
}

int converteASCII(char *string, char ascii[]){ 
    char temp[2];
    int i;    
    int cont = 0;
    int tam = strlen(string);
    for(i = 0; i < tam; i+=2){         
        temp[0]  = string[i];
        temp[1]  = string[i+1];
        sscanf(temp, "%hhx", &ascii[cont]);
        if (!isprint(ascii[cont]))
            return 0;
        cont++;    
   }
   return 1;
}



