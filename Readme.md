# Tecnologia Criptográfica

## Elementos do grupo:
### Nome | Número | Github
- Carla Cruz A80564 CarlaCruz146
- Adriana Meireles A82582 AdrianaMeireles80
- Pedro Freitas A80975	PedroFreitas90

## Alterações a Guiões

### G1
Neste guião as alterações foram efetuadas consoante os conselhos do professor.
#### Antes
Antes do feedback recebido depois da entrega, o mesmo programa encriptava e decifrava a mensagem encriptada no mesmo processo.
#### Depois
Após a alteração o processo de encriptação e decifrar da mensagem já são executados em processos diferentes. Para tal houve a necessidade de colocarmos a chave da cifra num ficheiro de texto, visto que era uma cifra simétrica e a chave teria de ser igual nos dois processos.
##### Data de alteração
16/12/2019

### G2
Neste guião as alterações foram efetuadas consoante os conselhos do professor, pois houve uma má interpretação do enunciado.
#### Antes
Antes do feedback tanto a encriptação como o decifrar da mensagem, era feitos no mesmo processo, em ambas as versões. Além disso na versão 2 houve um problema de interpretação do enunciado.
#### Depois
Na versão 1, onde teríamos de encriptar segundo uma password, essa password é pedida ao utilizador. Ele dá input dessa password, que irá sofrer um processo de derivação (*PBKDF2HMAC*) que irá devolver a password derivada e um *salt* . A mensagem é primeiro encriptada por uma cifra fernet cuja key é a password derivada. Depois o salt é adicionado ao início da mensagem, e toda esta sofre outro processo de encriptação segundo uma Key gerada aleatoriamente. Essa key é guardada no ficheiro *key* e está acessível a toda a gente. Já no processo de decrifrar, é também pedida uma password. Após isto, o processo vai ao ficheiro *key* para fazer a primeira desencriptação. Após isso pega nos 16 primeiros bytes (salt) e atravéds do input vai derivar a password. Se esta estiver correta, o processo será corretamente efectuado. 


Já na versão 2 a nossa interpretação levou-nos à seguinte sucessão de acontecimentos:
- É gerada uma chave aleatória através do `randomkey = Fernet.generate_key()` 
- Com a password dada pelo utilizador, derivamos (obtendo a password derivada e o salt usado) e encriptamos a *randomkey* com a cifra gerada com esta password derivada. Essa encriptação é escrita no ficheiro *Keystore.keystore*
- Com a chave aleatória criamos uma cifra Fernet: *randomcipher*
- Encriptamos o texto com esta cifra
- Adicionamos o salt À cabeça do texto encriptado
- Escrevemos a mensagem final no ficheiro *mensagem.enc*

##### Data de alteração
16/12/2019

### G5
Neste guião as alterações foram efetuadas devido ao uso de uma biblioteca diferente. Em todos os guiões anteriores, nós faziamos uso da biblioteca *criptography* , porém neste guião nós usamos a biblioteca *Cipher* que pertence ao **pycryptodome*. 
#### Antes
Antes do feedback fizemos 3 versões diferentes de cifras por blocos (AES, CBB e CTR). Todos estes modos foram implementados usando a biblioteca *Cipher*
#### Depois
Nesta nova versão implementamos os modos GCM (que é muito idêntico ao modo AES) e CTR.  Tentamos implementar o modo CBC mas obtivemos alguns problemas e não os conseguimos resolver. 

##### Data de alteração
16/12/2019

### G6
Neste guião as alterações foram efetuadas pois decidimos refazer o guião.
As alterações que foram feitas foi o modo de encriptação (e consequentemente) desencriptação e separar esses processos em métodos diferentes (em vez de estar tudo no meio do método process, de modo a ficar um código mais organizado ) 

##### Data de alteração
16/12/2019




