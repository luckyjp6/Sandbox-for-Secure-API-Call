# Sandbox for Secure API Call
此repo收錄課程「高等Unix」的大作業一。
透過實作sandbox.so達成library injection, API hijacking和GOT rewriting等一系列目的，實作技巧包括**parse ELF (Executable and Linkable Format)**、環境變數和shared library等。

## Usage
使用launcher載入sandbox.so、設定環境變數並執行目標程式。Launcher只載入```__libc_start_main```，其餘API重包將於```__libc_start_main```中執行。
```
Usage: ./launcher sandbox.so config.txt <target process> arg1 arg2 ...
```
環境變數包含：
- SANDBOX_CONFIG：供sandbox.so使用的configuration file路徑。
- LOGGER_FD：供sandbox.so輸出logger message的file descriptor。

## Sandbox
- 實作```__libc_start_main``` hijack目標程式的進入點，讀取```/proc/self/maps```獲得當前command的絕對路徑及記憶體起始位置，接著parse command檔案以取得Procedure Link Table (PLT)，再進一步將特定API function置換成自訂的function。
- 實作Parse ELF的程式碼（非直接取用如readelf等現有Linux command），首先取得ELF header並確認檔案合法性，接著取得section header，找到section name table，進而獲得需要的各section索引，包括：
    - ```.dynsym```：紀錄symbol名稱的offset。
    - ```.dynstr```：紀錄symbol名稱。
    - ```.rela.plt```：紀錄symbol各項資訊如symbol在```.dynsym```對應資訊的索引值、symbol在記憶體中相對程式起始位置的offset等。
- 實作自己的API functions（重新包裝過的API皆會輸出logger message。）
    - open：可在configuration file中建立黑名單禁止特定檔案開啟。嘗試開啟的檔案在黑名單中時，回傳-1並設定```errno```為EACCES；若要開啟的檔案是symbolic link，會追溯到原始檔案再比對黑名單。  
            
        e.g. 嘗試開啟黑名單中的檔案，command：```./launcher ./sandbox.so config.txt cat /etc/passwd```  
        ```
        [logger] open("/etc/passwd", 0, 0) = -1
        cat: /etc/passwd: Permission denied
        ```
    - read：
        - 讀取到的內容會記錄到log file中，命名形式：```{pid}-{fd}-read.log```
        - 可在configuration file中指定禁語。嘗試讀取的內容包括禁語時，關閉檔案並設定```errno```為EIO；當關鍵字剛好分成兩段個別讀取，也需偵測出，並做出處置，參見下例。  
        
            e.g., 關鍵字```forbidden```若分成```for```, ```bidden```兩段讀取（先讀三個byte再讀剩下的），當讀取```bidden```時會檢測到關鍵字。
            ```
            [logger] open("/tmp/test", 0, 0) = 5
            [logger] read(5, 0x7fb7b2db2000, 3) = 3
            for
            [logger] read(5, 0x7fb7b2db2000, 9999) = -1
            /tmp/test: Input/output error
            /tmp/test: Bad file descriptor
            ```
    - write：讀取到的內容會記錄到log file中，命名形式：```{pid}-{fd}-write.log```
    - connect：可在configuration file中建立黑名單禁止連線至特定IP或port。嘗試連接的對象在黑名單中時，回傳-1並設定```errno```為ECONNREFUSED。
    - getaddrinfo：可在configuration file中建立黑名單禁止解析特定host name。嘗試解析黑名單中的host name，回傳EAI_NONAME。
    - system：由```system```調用的command也需要被sandbox hijack和監控，其關係如下圖  

        e.g. ```process1``` calls ```system("/bin/sh")```
        ```
        - launcher
            |- process1
                |- /bin/sh
        ```
    
## Configuration File
以文字檔的形式呈現，改動configuration file無須重新編譯sandbox.so檔即可套用新設定。各API黑名單區塊中每一行為一個黑名單對象，格式如下：
```
BEGIN open-blacklist
/etc/passwd
/tmp/forbidden
END open-blacklist

BEGIN read-blacklist
forbidden
END read-blacklist

BEGIN connect-blacklist
www.nycu.edu.tw:4433
google.com:80
END connect-blacklist

BEGIN getaddrinfo-blacklist
www.ym.edu.tw
www.nctu.edu.tw
END getaddrinfo-blacklist
```

## 使用範例統整
範例皆使用上一個段落中的configuration file。
### open & read & write
![image](https://github.com/luckyjp6/Sandbox-for-Secure-API-Call/assets/96563567/9bcc68c2-0458-44f2-b908-a2cee5c25174)

### connect
（嘗試連線的IP在```connect```黑名單中，連線不會成功，而wget連線失敗會不停重新連線）
![image](https://github.com/luckyjp6/Sandbox-for-Secure-API-Call/assets/96563567/64e891db-bd4e-47a2-99d7-67e261fca5ac)

### getaddrinfo
（嘗試連線的host name在```getaddrinfo```黑名單中，請求不會成功）
![image](https://github.com/luckyjp6/Sandbox-for-Secure-API-Call/assets/96563567/0fc97d30-ffc2-4d88-a958-cfab7cf6ba21)

### system
![image](https://github.com/luckyjp6/Sandbox-for-Secure-API-Call/assets/96563567/ffdfe306-e8b6-4b52-8369-14c638742b13)
![image](https://github.com/luckyjp6/Sandbox-for-Secure-API-Call/assets/96563567/43c946f8-a10f-466b-9f86-fe46287f9207)

## 心得
其實比想像的複雜，大部分同學卡在parse ELF的地方，格式頗彎彎繞繞，只能說我相信前人這麼定義ELF一定有他的理由，我暫時還沒參透。後來多數同學選擇直接使用Linux指令```readelf```，實作parse ELF這段程式確實花時間，但成功做出來後挺有成就感的，也收穫很多，對ELF格式有更深一層了解！  
（主要是當時為了找到需要的section，翻了好多文件和許多前輩解說ELF、PLT、GOT的資料，嘗試了許久，走錯不少路）  

自訂API function的部分也不容易，因為可以控制的只有被hijack的這些API function，在read之前使用者做了什麼？檔案何時被關閉？這些都無從得知，所擁有的工具只是單純的API function，甚至不知道何時會被使用者呼叫，無法追蹤使用者的其他行動。  

歷經嘗試、失敗和思考後終於完成這次作業，收穫頗豐，第一次以另一個角度（API function）撰寫程式，這門課不停地顛覆我過去對資工領域淺薄的認知，第一次深入解析二進位檔案格式、第一次寫assembly（參見[收錄這門課程Lab們的repo](https://github.com/luckyjp6/Advance-Unix-Programming)或是[另一個實作簡易debugger的大作業二](https://github.com/luckyjp6/Simple-Debbuger)）和操作stack上的資料，除了這些之外，我也更熟練使用Linux系統，成長滿滿，謝謝老師和助教精心設計的課程。