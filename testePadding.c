#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void padding(char *string, int len);
static void unpadding(char *string, int len);

void main(){
    char palavra[200];
    char palavraHexa[400];
    int tam;
 
    printf("ASCII: ");
    while (scanf("%s", palavra)){       
        
        tam = strlen(palavra);

        for(int i = 0; i < tam;i++){        
            sprintf(palavraHexa+i*2,"%02x", palavra[i]);
        }

        padding(palavraHexa, strlen(palavraHexa));
        printf("Padding  : %s \n", palavraHexa);

        unpadding(palavraHexa, strlen(palavraHexa));
        printf("Unpadding: %s \n", palavraHexa);
        printf("ASCII: ");
    }   

}

static void padding(char *string, int len){ //Padrao utilizado PKCS#7
    int qdtBlocos32, bytesOcupados;
    int i;
    qdtBlocos32 = len/32;   //Obtem a quantidade de blocos completos
    bytesOcupados = len%32; //Obtem a quantidade de bytes usados no ultimo bloco

    if(bytesOcupados == 0){ //Caso a string tenha o tamanho multiplo de 16, preenche um novo blco com o num 0x20 (tamanho do bloco)
        for(i = 0; i < 32; i++){
            sprintf(string+qdtBlocos32*32+ i*2,"%02x", 32);//Converte 32 decimal para hexa (0x20)
        }
        string[qdtBlocos32*32 + 32] = '\0';
    }

    else {
        for(i = 0; i < 32 - bytesOcupados; i++){//O ultimo bloco eh preenchido com o valor da qtd de bytes livres
            sprintf(string + qdtBlocos32*32 + bytesOcupados + i*2,"%02x", 32 - bytesOcupados);
         }
        string[qdtBlocos32*32 + 32] = '\0';
    }
    
}

static void unpadding(char *string, int len){ //Padrao utilizado PKCS#7
    char temp[3];
    int qtdPadding;//Quantidade de bytes usados no padding
    int numP;//Numero usado para preencher o padding

    temp[0]  = string[len-2];//Ultimo numero sempre eh usado para calcular o padding
    temp[1]  = string[len-1];
    temp[2]  = '\0';    
    sscanf(temp, "%x", &qtdPadding);// Converte o num de hexa para decimal

    for(int i = qtdPadding; i > 2; i -= 2){
        temp[0]  = string[len - 2+i];
        temp[1]  = string[len - 1+i];
        temp[2]  = '\0';
        sscanf(temp, "%x", &numP);
        if(numP != qtdPadding){//Caso o numero usado para preencher seja diferente da qtd, retorna erro
            printf("Erro\n");
            return; 
        } 
    }
    string[len - qtdPadding] = '\0';//Descarta numeros usados no padding
}