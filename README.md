# Description
AES implementation in Common Lisp.
Written for readability with almost no performance optimizations.

# Performance
Lisp Version: sbcl-1.1.8-x86-64-darwin

## Clock cycles per byte
<table>
<tr><th></th> <th>2.26 GHz Intel Core 2 Duo</th> <th>2.8 GHz Intel i7</th></tr>
<tr><td>AES-128</td> <td>-</td> <td>17000</td></tr>
<tr><td>AES-192</td> <td>-</td> <td>21000</td></tr>
<tr><td>AES-256</td> <td>-</td> <td>25000</td></tr>
</table>

## Consing in bytes per 128 bit block
<table>
<tr><th></th> <th>bytes/th></tr>
<tr><td>AES-128</td> <td>79000 </td></tr>
<tr><td>AES-192</td> <td>95000 </td></tr>
<tr><td>AES-256</td> <td>111000</td></tr>
</table>
