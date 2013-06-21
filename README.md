# Description

AES implementation in Common Lisp.
Written for readability with almost no performance optimizations.

# Performance

<table>
<tr><th></th> <th>2.26 GHz Intel Core 2 Duo</th> <th>2.8 GHz Intel i7</th></tr>
<tr><th></th> <th></th>cycles/byte<th>cycles/byte</th></tr>
<tr><td>AES-128</td> <td>40000</td> <td>31000</td></tr>
<tr><td>AES-197</td> <td>47000</td> <td>     </td></tr>
<tr><td>AES-256</td> <td>55000</td> <td>     </td></tr>
</table>


