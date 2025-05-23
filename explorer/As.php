<?php
include 'i/head.php';
include 'i/pg.php';
$json = pgj("querymg " . $_GET["b"]);
if (! (isset ($json->response))) {
  echo "<h3>No response obtained!</h3>";
  exit(0);
} else if ($json->response != 'known') {
  echo "<h3>Not known " . $_GET["b"] . " " . $json->response . "</h3>";
  exit(0);
}
if (($json->dbdata[0]->type != "assetid") && ($json->dbdata[0]->type != "asset")) {
    header('Location: q.php?b=' . $_GET["b"]); die();
}
if ($json->dbdata[0]->type == 'assetid') {
  $ain = $_GET["b"];
  $ai = $json->dbdata[0];
  $ahn = $ai->assethash;
  $json = pgj("querymg " . $ahn);
  $ah = $json->dbdata[0];
} else if ($json->dbdata[0]->type == 'asset') {
  $ahn = $_GET["b"];
  $ah = $json->dbdata[0];
  $ain = $ah->assetid;
  $json = pgj("querymg " . $ain);
  $ai = $json->dbdata[0];
}
include 'i/search.php';
?>
<h1>Proofgold Asset</h1>
<table>
  <tr>
    <td><table><tr><th>asset id</th></tr><tr><td><?= $ain ?></td></tr></table></td>
    <td><table><tr><th>asset hash</th></tr><tr><td><?= $ahn ?></td></tr></table></td>
  </tr>
  <tr>
    <td><table><tr><th>bday / block</th></tr><tr><td><?= ablock($ai->block, $ah->bday) ?></td></tr></table></td>
    <td><table><tr><th>tx</th></tr><tr><td><?php if (isset($ai->tx)) {echo abbrv($ai->tx);} else {echo "none";} ?></td></tr></table></td>
  </tr>
  <tr>
    <td colspan="2"><table><tr><th>preasset</th></tr><tr><td><?= preasset($ah) ?></td></tr></table></td>
  </tr>
</table>

<hr/>

</body>
</html>
