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

#define TAM_BUFFER 256
static char recebido[TAM_BUFFER];

int main(int argc, char *argv[]){

   int option=-99;
   int ret,crypto;
   char *operacao = argv[1];
   if(argc==1) operacao = "none";
   
   if(strcmp(operacao,"c")==0) option=1;
      
   if(strcmp(operacao,"d")==0) option=2;
   
   if(strcmp(operacao,"h")==0) option=3;
   
   if(strcmp(operacao,"-h")==0) option=0;

   if(option >=1 && option <=3){
      crypto = open("/dev/crypto",O_RDWR);
      if(crypto < 0){
         perror("Falha ao acessar dispositivo...");
         return errno;
      }
   }
   
   switch (option)
   {
      case 1:
         printf("--:Criptografia:--\n");
         if(argc==2){printf("A opcao requer argumentos -- '%s'\n",operacao);goto syntax;}
         ret = write(crypto,argv[2],strlen(argv[2]));
         if(ret < 0){
            perror("Falha ao enviar dado ao dispositivo...");
            return errno;
         }
         ret = read(crypto,recebido,TAM_BUFFER);
         if(ret < 0){
            perror("Falha ao ler dado do dispositivo...");
            return errno;
         }
         printf("\nDado enviado: %s",argv[2]);
         printf("\nDado criptografado: %s\n",recebido);   
      break;
      case 2:
         printf("--<Descriptografia>--\n");
         if(argc==2){printf("A opcao requer argumentos -- '%s'\n",operacao);goto syntax;}
         ret = write(crypto,argv[2],strlen(argv[2]));
         if(ret < 0){
            perror("Falha ao enviar dado ao dispositivo...");
            return errno;
         }
         ret = read(crypto,recebido,TAM_BUFFER);
         if(ret < 0){
            perror("Falha ao ler dado do dispositivo...");
            return errno;
         }
         printf("\nDado enviado: %s",argv[2]);
         printf("\nDado descriptografado: %s\n",recebido); 

      break;
      case 3:
         printf("-#-Gerar Hash-#-\n");
         if(argc==2){printf("A opcao requer argumentos -- '%s'\n",operacao);goto syntax;}
         ret = write(crypto,argv[2],strlen(argv[2]));
         if(ret < 0){
            perror("Falha ao enviar dado ao dispositivo...");
            return errno;
         }
         ret = read(crypto,recebido,TAM_BUFFER);
         if(ret < 0){
            perror("Falha ao ler dado do dispositivo...");
            return errno;
         }
         printf("\nDado enviado: %s",argv[2]);
         printf("\nHash: %s\n",recebido); 
      
      break;
   case 0:
      printf(".:CryptoDev:. - Desenvolvido por Adriano, Fabio, Iago e Lucas\n");
      printf("Faz operaçoes de criptografia usando um LKM\n");
      printf("Como usar: ./crypto [OPERACAO] [DADO]\n...\n");
      printf("OPERACOES\n\t c - Criptografar\n\t d - Descriptografar\n\t h - Gerar Hash\n\t-h - Esta tela de ajuda\n\n");
      printf("DADO - Qualquer valor diferente de NULL\n");
      break;
   default:
   syntax:
      printf("Sintaxe invalida!!\n\n Exemplo: ./crypto [cdh] [DADO]... Tente './crypto -h' para ajuda.\n");
      return 0;
      break;
   }


   
   return 0;
}
