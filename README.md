# CryptoModule

# Introdução
Este projeto deverá ajudar a familiarizar-se com os detalhes de implementação de um módulo de kernel que faz uso da API criptográfica do kernel Linux. Espera-se que ao final do projeto, você possa ser capaz de implementar, compilar, instalar e testar um novo módulo de kernel que realize as funções de cifrar, decifrar e calcular o resumo criptográfico (hash) dos dados fornecidos pelo usuário.

# Descrição do projeto

O projeto consiste na implementação de um módulo de kernel capaz de cifrar, decifrar e calcular resumo criptográfico *(hash)* dos dados fornecidos pelo usuário. Além do módulo de kernel, também deve ser implementado um programa em espaço de usuário para testar o módulo desenvolvido.

O módulo de kernel desenvolvido deve possuir a função de um driver de dispositivo criptográfico *(crypto device driver)* capaz de receber requisições e enviar respostas através do arquivo de dispositivo `/dev/crypto`.

Ao carregar o módulo de kernel, deve-se informar no parâmetro `key` a chave simétrica e no parâmetro `iv` o vetor de inicialização que serão usados para cifrar e decifrar os dados. Tanto a chave simétrica quanto o vetor de inicialização correspondem a uma string representada em hexadecimal (cada byte corresponde a dois dígitos hexa). A carga do módulo deve ser executada como no exemplo a seguir:
```shell
insmod cryptomodule.ko key=”0123456789ABCDEF” iv=”0123456789ABCDEF”
```
O envio de requisições ao dispositivo criptográfico deve ser realizado através de operações de escrita no arquivo de dispositivo. As requisições ao dispositivo devem ser realizadas no seguinte formato:

`operação dados`

onde:

- `operação`: corresponde a um caracter que define qual operação será realizada pelo dispositivo, sendo permitidas as operações de cifrar (`c`), decifrar (`d`) ou calcular o resumo criptográfico (`h`);

- `dados`: corresponde a uma string contendo os dados sobre os quais a operação será realizada representados em hexadecimal (cada byte corresponde a dois dígitos hexa).

O envio da resposta do dispositivo criptográfico contendo o resultado da operação solicitada deve ser realizado através de operações de leitura no arquivo de dispositivo. 

- Para a operação de cifrar (`c`), a resposta deve ser uma string correspondendo aos dados fornecidos durante a requisição, cifrados com o algoritmo AES em modo CBC utilizando-se a chave fornecida durante a carga do módulo, representados em hexadecimal (cada byte corresponde a dois dígitos hexa).

- Para a operação de decifrar (`d`), a resposta deve ser uma string correspondendo aos dados fornecidos durante a requisição representados em hexadecimal (cada byte corresponde a dois dígitos hexa), decifrados com o algoritmo AES em modo CBC utilizando-se a chave fornecida durante a carga do módulo.

- Para a operação de cálculo de resumo criptográfico (`h`), a resposta deve ser uma string correspondendo ao resumo criptográfico em hexadecimal dos dados fornecidos durante a requisição, utilizando-se o algoritmo SHA1.

Para testar o correto funcionamento do driver de dispositivo criptográfico, deve ser implementado um programa em espaço de usuário que permita abrir o arquivo de dispositivo, enviar uma requisição fornecida pelo usuário (através de uma operação de escrita no arquivo de dispositivo) e exibir a resposta fornecida pelo dispositivo criptográfico (através de uma operação de leitura no arquivo de dispositivo).

O módulo de kernel desenvolvido também deve obrigatoriamente fazer uso de `MUTEX LOCKS` para bloquear um processo em espaço de usuário caso este processo acesse o arquivo de dispositivo `/dev/crypto` enquanto ele estiver sendo utilizado por outro processo em espaço de usuário.

Tanto o módulo de kernel quanto o programa de usuário devem ser compilados através de um Makefile.

# Instruções 

Como dito acima, para testar as funcionalidades do módulo de criptografia criamos um programa em espaço de usuário que envia requisições para o módulo, para o correto funcionamento é necessario executa-lo desta maneira:

`sudo ./crypto [operação] [dado]`

onde, 
- `sudo` é necessario para se adquirir privilégios administrativos para acesso a pasta `/dev/crypto`. 
- `operação` são as opçoes descritas na seção anterior.
- `dados` qualquer valor diferente de `NULL`.

Adicionando a flag `--hexa` após o dado, fará com que o mesmo seja tratado como hexadecimal.

**Obs.:** Essa mesma explicação pode ser acessada digitando `sudo ./crypto -h`. 

# Compilando

**Certifique-se de que os pacotes `deb-src` estejam adicionados ao seu `sources.list`, e devidamente instalados**

Use: 
- `make`, para compilar todos os programas necessarios. 
- `make new` para substituir o módulo atual. 
- `make crypto` para somente o programa de testes 
- `make clean` para limpar os arquivos temporários de compilação.

# Material Complementar

Documentação do Kernel: pasta Documentation/crypto no código fonte do kernel.

[Linux Kernel Crypto API](https://www.kernel.org/doc/html/v4.12/crypto/index.html)

[Writing a Linux Kernel Module - Part 2: A Character Device](http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device)

[derekmolloy](https://github.com/derekmolloy) GitHub  Repo - [exploringBB](https://github.com/derekmolloy/exploringBB/tree/master/extras/kernel/)

[Simple demo explaining usage of the Linux CryptoAPI](http://www.logix.cz/michal/devel/cryptodev/cryptoapi-demo.c.xp)

# Autores

**Adriano Munin** - [adrianomunin](https://github.com/adrianomunin)

**Fabio Irokawa** - [fabioirokawa](https://github.com/fabioirokawa)

**Iago Lourenço**  [iaglourenco](https://github.com/iaglourenco)

**Lucas Coutinho** - [lucasrcoutinho](https://github.com/lucasrcoutinho)


# Licença

Este projeto esta licenciado pela GPL v3.0 License - veja [LICENSE](LICENSE) para mais detalhes.
