<?php
include 'i/head.php';
include 'i/pg.php';
$json = pgj("querymg " . $_GET["b"]);
if (!isset($json->response) || $json->response != "known") {echo "ERROR incorrect querymg answer\n"; die();}
$v = $json->dbdata[0];
if ($v->type != "block") {
    header('Location: q.php?b=' . $_GET["b"]); die();
}
include 'i/search.php';
?>
<h1>Proofgold Block</h1>
<table>
  <tr>
<td><table><tr><th>height</th></tr><tr><td><?= ($_GET["b"] == "146d68bb8ee74c7a777e4efae7534e5ed3250ff2c3122e654fc4232cfdae5423" ? 1 : $v->height) ?></td></tr></table></td>
    <td><table><tr><th>creation</th></tr><tr><td><?= gmdate("Y-m-d H:i:s \G\M\T", $v->timestamp) ?></td></tr></table></td>
  </tr>
  <tr>
       <td><table><tr><th>previous</th></tr><tr><td><?= isset($v->prevblock) ? ablock($v->prevblock->block, $v->height - 1) : "-" ?></td></tr></table></td>
    <td><table><tr><th>stake address</th></tr><tr><td>
      <?= isset($v->stakeassetid) ? abbrvaddrasset($v->stakeaddress, $v->stakeassetid) : "Pure Burn " . abbrvaddr($v->stakeaddress) ?>
<br/>
          <?= isset($v->prevblock) ? (
 "<a href=\"https://blockchair.com/litecoin/transaction/" . $v->prevblock->ltcburntx . "\">LBT:" . substr($v->prevblock->ltcburntx, 0, 5) . "</a>") : "-" ?>

                                                                    
    </td></tr></table></td>
  </tr>
  <tr>
  <td><table><tr><th>transactions</th></tr><tr><td>
       <?php foreach ($v->txs as $tx) { echo abbrvstx($tx) . "<br/>"; } ?>
    </td></tr></table></td>
    <td><table><tr><th>outputs</th></tr><tr><td>
       <?php foreach ($v->coinstk->vout as $vo) { echo onevout($vo); } ?>
    </td></tr></table></td>
  </tr>
<!--  <tr>
    <td><table><tr><th>ledger root</th></tr><tr><td><?= abbrv($v->newledgerroot) ?></td></tr></table></td>
    <td><table><tr><th>newtheoryroot</th></tr><tr><td><?= abbrv($v->newtheoryroot) ?></td></tr></table></td>
  </tr>-->
  </table></td>

   </tr>
</table>

</body>
</html>
