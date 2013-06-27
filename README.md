# Description
AES implementation in Common Lisp.

- 128-bit data types
- optimization with pre-calculated tables.

# Performance
Lisp Version: sbcl-1.1.8-x86-64-darwin

## Clock cycles per byte
<table>
<tr><th></th> <th>2.26 GHz Intel Core 2 Duo</th> <th>2.8 GHz Intel i7</th></tr>
<tr><td>AES-128</td> <td>-</td> <td>6500</td></tr>
<tr><td>AES-192</td> <td>-</td> <td>7600</td></tr>
<tr><td>AES-256</td> <td>-</td> <td>8700</td></tr>
</table>

## Consing in bytes per 128 bit block
<table>
<tr><th></th> <th>bytes</th></tr>
<tr><td>AES-128</td> <td>38000 </td></tr>
<tr><td>AES-192</td> <td>44000 </td></tr>
<tr><td>AES-256</td> <td>51000</td></tr>
</table>
