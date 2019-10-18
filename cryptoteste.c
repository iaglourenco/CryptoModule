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
void converteHexa(char *string, char *hexa);
void insereOpcInicio(char *entrada, char *saida, char opc);

int main(int argc, char *argv[]){

   uid_t uid=getuid();
   int option=-99;
   int ret,crypto;
   char *operacao = argv[1];
   char msgKernelHexa[200];
   char temp[200];
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
   if(strcmp(operacao,"-h")==0) option=0;

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
   
   switch (option)
   {
      case 1:
         printf("--:Criptografia:--\n");

         converteHexa(argv[2], temp);

         insereOpcInicio(temp,msgKernelHexa,'c');
         
         ret = write(crypto,msgKernelHexa,strlen(msgKernelHexa));
         if(ret < 0){
            perror("Falha ao enviar dado ao dispositivo...");
            return errno;
         }
         
         ret = read(crypto,recebido,TAM_BUFFER);
         if(ret < 0){
            perror("Falha ao ler dado do dispositivo...");
            return errno;
         }
         printf("\nDado enviado: %s",msgKernelHexa+1);
         printf("\nDado criptografado: %s\n",recebido);   
      break;

      case 2:
         printf("--<Descriptografia>--\n");
          
         insereOpcInicio(argv[2], msgKernelHexa, 'd');
         
         ret = write(crypto,msgKernelHexa,strlen(msgKernelHexa));
         if(ret < 0){
            perror("Falha ao enviar dado ao dispositivo...");
            return errno;
         }
         ret = read(crypto,recebido,TAM_BUFFER);
         if(ret < 0){
            perror("Falha ao ler dado do dispositivo...");
            return errno;
         }
         printf("\nDado enviado: %s",msgKernelHexa+1);
         printf("\nDado descriptografado: %s\n",recebido); 

      break;

      case 3:
         printf("-#-Gerar Hash-#-\n");

         converteHexa(argv[2], temp);

         insereOpcInicio(temp,msgKernelHexa,'h');
         

         ret = write(crypto,msgKernelHexa,strlen(msgKernelHexa));
         if(ret < 0){
            perror("Falha ao enviar dado ao dispositivo...");
            return errno;
         }
         ret = read(crypto,recebido,TAM_BUFFER);
         if(ret < 0){
            perror("Falha ao ler dado do dispositivo...");
            return errno;
         }
         printf("\nDado enviado: %s",msgKernelHexa+1);
         printf("\nHash: %s\n",recebido); 
      
      break;
   case 0:
      printf(".:CryptoDev:. - Desenvolvido por Adriano, Fabio, Iago e Lucas\n");
      printf("Faz operaçoes de criptografia usando um LKM\n");
      printf("Como usar: ./crypto [OPERACAO] [DADO]\n------\n");
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



void converteHexa(char *string, char hexa[]){
   int tam = strlen(string);
   int i;
   for(i = 0; i < tam; i++){        
      sprintf(hexa+i*2,"%02x", string[i]);
   }
   hexa[(i*2)+1]='\0'; 
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
