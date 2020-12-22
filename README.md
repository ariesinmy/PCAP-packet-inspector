# NPhw3

請寫出一個封包檢視工具，具有底下功能：

可以讀入既有的pcap檔案，並對於檔案中的每個封包顯示(每個封包一行)：

1. 那個封包擷取的時間戳記(Time)

2. 來源MAC位址、目的MAC位址、Ethernet type欄位(Src-mac and Dst-mac)

3. 如果那個封包是IP封包，則再多顯示來源IP位址與目的地IP位址(Src-addr and Dst-addr)

4. 如果那個封包是TCP或UDP封包，則再多顯示來源port號碼與目的port號碼(Src-port and Dst-port)
