# FirewallNetfilterQueue

Реализация простого фильтра DNS пакетов. Фильтрует только пакеты-ответы. На вход скрипт принимает номер очереди для фильтрации и путь до файла (подрбнее main.py --help). Файл с правилами состоит из правил вида:
```
accept/drop [name=py_reg_expr] [type=py_reg_expr] [data=py_reg_expr] [ttl='TTL'] [aa='true']
```
Фильтруя соответсвенно rrname, type, rdata. Правила применяются последовательно, если ни одно правило не подошло, пакет будет пропущен
Пример файла с правилами:
```
accept name='\w+.ru'
accept name='ya.com' type='A'
accept data='87.240.137.164'
drop name='\w+'
```

Флаг ttl будет блокировать все пакеты с ttl ниже порогового. Флак аа='true' будет блокировать все не авторитетные ответы.
