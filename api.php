<?php
session_start();
header('Content-Type: application/json; charset=utf-8');
$allowedOrigins = ['https://copa433.site', 'https://www.copa433.site', 'http://localhost', 'http://127.0.0.1'];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowedOrigins, true)) {
    header('Access-Control-Allow-Origin: ' . $origin);
} else {
    header('Access-Control-Allow-Origin: https://copa433.site');
}
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit; }

$host = 'localhost';
$db   = 'u289267434_copa433';
$user = 'u289267434_copa433';
$pass = 'Zonete@13';

try {
    $pdo = new PDO(
        "mysql:host=$host;dbname=$db;charset=utf8mb4",
        $user,
        $pass,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
    );
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['erro' => 'Falha na conexao: ' . $e->getMessage()]);
    exit;
}

function hasColumn(PDO $pdo, string $table, string $column): bool {
    $stmt = $pdo->prepare("
        SELECT COUNT(*) c
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = ?
          AND COLUMN_NAME = ?
    ");
    $stmt->execute([$table, $column]);
    return intval($stmt->fetch()['c'] ?? 0) > 0;
}

function nomeBase(string $nome): string {
    $n = trim($nome);
    $n = preg_replace('/\s*[\(\[]?\d{4}[\)\]]?\s*$/u', '', $n);
    return trim($n);
}

function garantirTabelasConta(PDO $pdo): void {
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS usuarios (
            id INT AUTO_INCREMENT PRIMARY KEY,
            usuario VARCHAR(80) NOT NULL UNIQUE,
            email VARCHAR(120) NULL UNIQUE,
            senha_hash VARCHAR(255) NOT NULL,
            nome_time VARCHAR(80) NOT NULL DEFAULT 'Meu Time',
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");
    // Adiciona coluna email se tabela já existia sem ela
    if (!hasColumn($pdo, 'usuarios', 'email')) {
        $pdo->exec("ALTER TABLE usuarios ADD COLUMN email VARCHAR(120) NULL UNIQUE AFTER usuario");
    }
    // Adiciona coluna escudo (base64 do escudo do time)
    if (!hasColumn($pdo, 'usuarios', 'escudo')) {
        $pdo->exec("ALTER TABLE usuarios ADD COLUMN escudo MEDIUMTEXT NULL AFTER nome_time");
    }
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS partidas_usuario (
            id INT AUTO_INCREMENT PRIMARY KEY,
            usuario_id INT NOT NULL,
            campeao TINYINT(1) NOT NULL DEFAULT 0,
            pontos INT NOT NULL DEFAULT 0,
            msg VARCHAR(255) NULL,
            ovr INT NOT NULL DEFAULT 0,
            time_nome VARCHAR(80) NOT NULL DEFAULT 'Meu Time',
            escalacao_json LONGTEXT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_usuario (usuario_id),
            CONSTRAINT fk_partidas_usuario FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS game_tokens (
            id INT AUTO_INCREMENT PRIMARY KEY,
            usuario_id INT NOT NULL,
            token CHAR(64) NOT NULL UNIQUE,
            usado TINYINT(1) NOT NULL DEFAULT 0,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_gt_token (token),
            INDEX idx_gt_usuario (usuario_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS reset_tokens (
            id INT AUTO_INCREMENT PRIMARY KEY,
            usuario_id INT NOT NULL,
            token CHAR(6) NOT NULL,
            expira_em DATETIME NOT NULL,
            usado TINYINT(1) NOT NULL DEFAULT 0,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_token (token),
            CONSTRAINT fk_reset_usuario FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");
}

function usuarioLogado(PDO $pdo): ?array {
    $id = intval($_SESSION['uid'] ?? 0);
    if (!$id) return null;
    $st = $pdo->prepare("SELECT id, usuario, email, nome_time, escudo FROM usuarios WHERE id = ?");
    $st->execute([$id]);
    $u = $st->fetch();
    return $u ?: null;
}
function iniciarModuloConta(PDO $pdo): bool {
    try {
        garantirTabelasConta($pdo);
        return true;
    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['erro' => 'Falha ao iniciar modulo de conta']);
        return false;
    }
}

$action = $_GET['action'] ?? '';

switch ($action) {
    case 'conta_status':
        if (!iniciarModuloConta($pdo)) break;
        $u = usuarioLogado($pdo);
        if (!$u) {
            echo json_encode(['logado' => false]);
            break;
        }
        echo json_encode(['logado' => true, 'usuario' => $u]);
        break;

    case 'conta_registrar':
        if (!iniciarModuloConta($pdo)) break;
        $body = json_decode(file_get_contents('php://input'), true);
        $usuario  = substr(trim((string)($body['usuario']   ?? '')), 0, 80);
        $email    = strtolower(trim((string)($body['email'] ?? '')));
        $senha    = (string)($body['senha'] ?? '');
        $nomeTime = substr(trim((string)($body['nome_time'] ?? 'Meu Time')), 0, 80);
        if ($usuario === '' || $email === '' || strlen($senha) < 4) {
            http_response_code(400);
            echo json_encode(['erro' => 'Usuário, e-mail e senha (mín. 4 caracteres) são obrigatórios']);
            break;
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            http_response_code(400);
            echo json_encode(['erro' => 'E-mail inválido']);
            break;
        }
        // Verificar unicidade antes de inserir (mensagem mais clara)
        $chkU = $pdo->prepare("SELECT 1 FROM usuarios WHERE usuario = ?");
        $chkU->execute([$usuario]);
        if ($chkU->fetch()) { http_response_code(400); echo json_encode(['erro' => 'Usuário já existe']); break; }
        $chkE = $pdo->prepare("SELECT 1 FROM usuarios WHERE email = ?");
        $chkE->execute([$email]);
        if ($chkE->fetch()) { http_response_code(400); echo json_encode(['erro' => 'E-mail já cadastrado']); break; }
        $hash = password_hash($senha, PASSWORD_DEFAULT);
        $st = $pdo->prepare("INSERT INTO usuarios (usuario, email, senha_hash, nome_time) VALUES (?, ?, ?, ?)");
        $st->execute([$usuario, $email, $hash, $nomeTime ?: 'Meu Time FC']);
        $_SESSION['uid'] = intval($pdo->lastInsertId());
        echo json_encode(['sucesso' => true]);
        break;

    case 'conta_login':
        if (!iniciarModuloConta($pdo)) break;
        $body  = json_decode(file_get_contents('php://input'), true);
        $login = trim((string)($body['login'] ?? $body['usuario'] ?? ''));
        $senha = (string)($body['senha'] ?? '');
        // Aceita login por usuário OU e-mail
        $isEmail = filter_var($login, FILTER_VALIDATE_EMAIL);
        if ($isEmail) {
            $st = $pdo->prepare("SELECT id, usuario, email, senha_hash, nome_time, escudo FROM usuarios WHERE email = ?");
        } else {
            $st = $pdo->prepare("SELECT id, usuario, email, senha_hash, nome_time, escudo FROM usuarios WHERE usuario = ?");
        }
        $st->execute([strtolower($login)]);
        $u = $st->fetch();
        if (!$u) {
            // tenta o outro campo como fallback
            $st2 = $pdo->prepare("SELECT id, usuario, email, senha_hash, nome_time, escudo FROM usuarios WHERE usuario = ? OR email = ?");
            $st2->execute([$login, strtolower($login)]);
            $u = $st2->fetch();
        }
        if (!$u || !password_verify($senha, (string)$u['senha_hash'])) {
            http_response_code(401);
            echo json_encode(['erro' => 'Usuário/e-mail ou senha inválidos']);
            break;
        }
        $_SESSION['uid'] = intval($u['id']);
        echo json_encode(['sucesso' => true, 'usuario' => $u['usuario']]);
        break;

    case 'conta_reset_solicitar':
        if (!iniciarModuloConta($pdo)) break;
        $body  = json_decode(file_get_contents('php://input'), true);
        $email = strtolower(trim((string)($body['email'] ?? '')));
        $st    = $pdo->prepare("SELECT id FROM usuarios WHERE email = ?");
        $st->execute([$email]);
        $u = $st->fetch();
        if (!$u) {
            // Não revelar se e-mail existe; responde sucesso mesmo assim
            echo json_encode(['sucesso' => true]);
            break;
        }
        $token = str_pad(strval(random_int(0, 999999)), 6, '0', STR_PAD_LEFT);
        $expira = date('Y-m-d H:i:s', time() + 1800); // 30 min
        $pdo->prepare("DELETE FROM reset_tokens WHERE usuario_id = ?")->execute([$u['id']]);
        $pdo->prepare("INSERT INTO reset_tokens (usuario_id, token, expira_em) VALUES (?, ?, ?)")
            ->execute([$u['id'], $token, $expira]);
        // Envia e-mail
        $assunto = '=?UTF-8?B?' . base64_encode('Redefinição de senha — Copa433') . '?=';
        $msg     = "Seu código de redefinição de senha para o Copa433 é:\n\n$token\n\nVálido por 30 minutos. Se não solicitou, ignore este e-mail.";
        $headers = "From: Copa433 <noreply@copa433.site>\r\nContent-Type: text/plain; charset=UTF-8";
        @mail($email, $assunto, $msg, $headers);
        echo json_encode(['sucesso' => true]);
        break;

    case 'conta_reset_confirmar':
        if (!iniciarModuloConta($pdo)) break;
        $body      = json_decode(file_get_contents('php://input'), true);
        $email     = strtolower(trim((string)($body['email']     ?? '')));
        $token     = trim((string)($body['token']     ?? ''));
        $novaSenha = (string)($body['nova_senha'] ?? '');
        if (strlen($novaSenha) < 4) { http_response_code(400); echo json_encode(['erro' => 'Senha muito curta']); break; }
        $st = $pdo->prepare("
            SELECT rt.id, rt.usuario_id
            FROM reset_tokens rt
            JOIN usuarios u ON u.id = rt.usuario_id
            WHERE u.email = ? AND rt.token = ? AND rt.usado = 0 AND rt.expira_em > NOW()
        ");
        $st->execute([$email, $token]);
        $row = $st->fetch();
        if (!$row) { http_response_code(400); echo json_encode(['erro' => 'Código inválido ou expirado']); break; }
        $pdo->prepare("UPDATE usuarios SET senha_hash = ? WHERE id = ?")
            ->execute([password_hash($novaSenha, PASSWORD_DEFAULT), $row['usuario_id']]);
        $pdo->prepare("UPDATE reset_tokens SET usado = 1 WHERE id = ?")
            ->execute([$row['id']]);
        echo json_encode(['sucesso' => true]);
        break;

    case 'conta_logout':
        if (!iniciarModuloConta($pdo)) break;
        unset($_SESSION['uid']);
        echo json_encode(['sucesso' => true]);
        break;

    case 'conta_nome_time':
        if (!iniciarModuloConta($pdo)) break;
        $u = usuarioLogado($pdo);
        if (!$u) {
            http_response_code(401);
            echo json_encode(['erro' => 'Nao autenticado']);
            break;
        }
        $body = json_decode(file_get_contents('php://input'), true);
        $nomeTime = substr(trim((string)($body['nome_time'] ?? '')), 0, 80);
        if ($nomeTime === '') $nomeTime = 'Meu Time';
        $st = $pdo->prepare("UPDATE usuarios SET nome_time = ? WHERE id = ?");
        $st->execute([$nomeTime, intval($u['id'])]);
        echo json_encode(['sucesso' => true]);
        break;

    case 'conta_salvar_escudo':
        if (!iniciarModuloConta($pdo)) break;
        $u = usuarioLogado($pdo);
        if (!$u) { http_response_code(401); echo json_encode(['erro' => 'Nao autenticado']); break; }
        $body = json_decode(file_get_contents('php://input'), true);
        $escudo = (string)($body['escudo'] ?? '');
        // Validate: must be a data URL image (png/jpg/gif/webp/svg)
        if ($escudo !== '' && !preg_match('/^data:image\/(png|jpeg|gif|webp|svg\+xml);base64,/', $escudo)) {
            http_response_code(400); echo json_encode(['erro' => 'Formato de imagem inválido']); break;
        }
        // Limit to ~500KB base64
        if (strlen($escudo) > 700000) {
            http_response_code(400); echo json_encode(['erro' => 'Imagem muito grande (máx. ~500KB)']); break;
        }
        $st = $pdo->prepare("UPDATE usuarios SET escudo = ? WHERE id = ?");
        $st->execute([$escudo ?: null, intval($u['id'])]);
        echo json_encode(['sucesso' => true]);
        break;

    case 'conta_historico':
        if (!iniciarModuloConta($pdo)) break;
        $u = usuarioLogado($pdo);
        if (!$u) {
            http_response_code(401);
            echo json_encode(['erro' => 'Nao autenticado']);
            break;
        }
        $uid = intval($u['id']);
        $stats = $pdo->prepare("
            SELECT COUNT(*) tentativas,
                   SUM(CASE WHEN campeao = 1 THEN 1 ELSE 0 END) vitorias,
                   SUM(CASE WHEN campeao = 0 THEN 1 ELSE 0 END) derrotas,
                   MAX(ovr) melhor_ovr,
                   MAX(pontos) melhor_pontos
            FROM partidas_usuario
            WHERE usuario_id = ?
        ");
        $stats->execute([$uid]);
        $s = $stats->fetch() ?: ['tentativas' => 0, 'vitorias' => 0, 'derrotas' => 0, 'melhor_ovr' => 0, 'melhor_pontos' => 0];

        $recentes = $pdo->prepare("
            SELECT id, campeao, pontos, ovr, time_nome, msg, escalacao_json, criado_em
            FROM partidas_usuario
            WHERE usuario_id = ?
            ORDER BY criado_em DESC
            LIMIT 20
        ");
        $recentes->execute([$uid]);
        $partidas = $recentes->fetchAll();
        foreach ($partidas as &$p) {
            $p['escalacao'] = json_decode((string)($p['escalacao_json'] ?? '[]'), true) ?: [];
            $p['campeao'] = (bool)$p['campeao'];
            unset($p['escalacao_json']);
        }
        unset($p);
        echo json_encode(['usuario' => $u, 'stats' => $s, 'partidas' => $partidas]);
        break;

    case 'iniciar_partida':
        if (!iniciarModuloConta($pdo)) break;
        $u = usuarioLogado($pdo);
        if (!$u) { http_response_code(401); echo json_encode(['erro' => 'Nao autenticado']); break; }
        // rate limit: max 30 partidas iniciadas nos últimos 60 min
        $rl = $pdo->prepare("SELECT COUNT(*) c FROM game_tokens WHERE usuario_id=? AND criado_em > DATE_SUB(NOW(), INTERVAL 60 MINUTE)");
        $rl->execute([intval($u['id'])]);
        if (intval($rl->fetch()['c']) >= 30) {
            http_response_code(429);
            echo json_encode(['erro' => 'Muitas partidas em sequência. Aguarde alguns minutos.']);
            break;
        }
        // limpa tokens velhos do usuário (> 3h)
        $pdo->prepare("DELETE FROM game_tokens WHERE usuario_id=? AND criado_em < DATE_SUB(NOW(), INTERVAL 3 HOUR)")->execute([intval($u['id'])]);
        $tok = bin2hex(random_bytes(32));
        $pdo->prepare("INSERT INTO game_tokens (usuario_id, token) VALUES (?, ?)")->execute([intval($u['id']), $tok]);
        echo json_encode(['token' => $tok]);
        break;

    case 'salvar_partida':
        if (!iniciarModuloConta($pdo)) break;
        $u = usuarioLogado($pdo);
        if (!$u) {
            http_response_code(401);
            echo json_encode(['erro' => 'Nao autenticado']);
            break;
        }
        $body = json_decode(file_get_contents('php://input'), true);

        // validar token de partida
        $gameTok = trim((string)($body['game_token'] ?? ''));
        if ($gameTok !== '') {
            $gtSt = $pdo->prepare("SELECT id, usado FROM game_tokens WHERE token=? AND usuario_id=? AND criado_em > DATE_SUB(NOW(), INTERVAL 3 HOUR)");
            $gtSt->execute([$gameTok, intval($u['id'])]);
            $gt = $gtSt->fetch();
            if (!$gt) {
                http_response_code(403);
                echo json_encode(['erro' => 'Token de partida inválido ou expirado']);
                break;
            }
            if ($gt['usado']) {
                http_response_code(403);
                echo json_encode(['erro' => 'Resultado já registrado']);
                break;
            }
            $pdo->prepare("UPDATE game_tokens SET usado=1 WHERE id=?")->execute([$gt['id']]);
        }

        // validar valores dentro de ranges razoáveis
        $campeao = !empty($body['campeao']) ? 1 : 0;
        $pontos = max(0, min(300, intval($body['pontos'] ?? 0)));
        $ovr = max(50, min(99, intval($body['ovr'] ?? 0)));
        $msg = substr(trim((string)($body['msg'] ?? '')), 0, 255);
        $msgValidas = ['Campeão', 'Final', 'Semifinal', 'Quartas de Final', 'Fase de Grupos'];
        $msgOk = $msg === '' || array_reduce($msgValidas, fn($c, $v) => $c || str_contains($msg, $v), false);
        if (!$msgOk) $msg = 'Fase de Grupos';
        // campeão só pode ter pontos >= 100
        if ($campeao && $pontos < 100) $pontos = 100;
        if (!$campeao && $pontos >= 200) $pontos = 60;

        $timeNome = substr(trim((string)($body['time_nome'] ?? ($u['nome_time'] ?? 'Meu Time'))), 0, 80);
        $escalacao = json_encode(($body['escalacao'] ?? []), JSON_UNESCAPED_UNICODE);
        $st = $pdo->prepare("
            INSERT INTO partidas_usuario (usuario_id, campeao, pontos, msg, ovr, time_nome, escalacao_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ");
        $st->execute([intval($u['id']), $campeao, $pontos, $msg, $ovr, $timeNome ?: 'Meu Time', $escalacao]);
        // Adicionar pontos pela partida
        ensurePontosTabelas($pdo);
        $ptsPartida = 0;
        if ($campeao) $ptsPartida = 100 + max(0, $ovr - 80);
        elseif (str_contains($msg ?? '', 'Final'))   $ptsPartida = 60;
        elseif (str_contains($msg ?? '', 'Semi'))    $ptsPartida = 40;
        elseif (str_contains($msg ?? '', 'Quartas')) $ptsPartida = 20;
        else $ptsPartida = 5;
        if ($ptsPartida > 0) adicionarPontos($pdo, intval($u['id']), $ptsPartida, 'partida_'.(int)$campeao);
        // Retornar total de pontos atualizado
        $ptRow2 = $pdo->prepare("SELECT total_pontos FROM usuario_pontos WHERE usuario_id=?");
        $ptRow2->execute([intval($u['id'])]);
        $r2 = $ptRow2->fetch();
        $totalPts2 = $r2 ? intval($r2['total_pontos']) : 0;
        echo json_encode(['sucesso' => true, 'pontos_ganhos' => $ptsPartida, 'total_pontos' => $totalPts2, 'liga' => ligaDosPontos($totalPts2)]);
        break;

    case 'draft_init':
        try {
            // Auto-cria rankings se não existir
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS rankings (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    usuario VARCHAR(100) NOT NULL,
                    pontos INT NOT NULL DEFAULT 0,
                    time_sorteado INT NOT NULL,
                    decada_sorteada VARCHAR(40) NULL,
                    criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_pontos (pontos DESC)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            ");

            // Detecta colunas opcionais da tabela times
            $hasSigla       = hasColumn($pdo, 'times', 'sigla');
            $hasEraT        = hasColumn($pdo, 'times', 'era');
            $hasOvrT        = hasColumn($pdo, 'times', 'ovr');
            $hasCompT       = hasColumn($pdo, 'times', 'competicao');
            $colSiglaSelect = $hasSigla ? 'sigla'       : "UPPER(SUBSTRING(nome, 1, 4)) AS sigla";
            $colSiglaJoin   = $hasSigla ? 't.sigla'     : "UPPER(SUBSTRING(t.nome, 1, 4)) AS sigla";
            $colCorPrimaria = hasColumn($pdo, 'times', 'cor_primaria') ? 'cor_primaria' : "NULL AS cor_primaria";
            $colEraSelect   = $hasEraT  ? 'era'         : "NULL AS era";
            $colOvrSelect   = $hasOvrT  ? 'ovr'         : "NULL AS ovr";
            $colCompSelect  = $hasCompT ? 'competicao'  : "NULL AS competicao";

            $times = $pdo->query("SELECT id, nome, $colSiglaSelect, $colEraSelect, $colOvrSelect, $colCompSelect, $colCorPrimaria FROM times ORDER BY nome")->fetchAll();

            if (empty($times)) {
                echo json_encode(['times' => [], 'jogadores' => [], 'combos' => [], 'aviso' => 'Banco sem times. Importe o SQL de seed.']);
                break;
            }

            // Detecta colunas de posição do jogador (vários nomes possíveis)
            if (hasColumn($pdo, 'jogadores', 'posicoes')) {
                $colPos = 'j.posicoes';
            } elseif (hasColumn($pdo, 'jogadores', 'posicao')) {
                $colPos = 'j.posicao';
            } elseif (hasColumn($pdo, 'jogadores', 'posicao1')) {
                $hasPosicao2 = hasColumn($pdo, 'jogadores', 'posicao2');
                $colPos = $hasPosicao2
                    ? "CONCAT(j.posicao1, IF(j.posicao2 IS NOT NULL AND j.posicao2 != '', CONCAT('/', j.posicao2), ''))"
                    : 'j.posicao1';
            } else {
                $colPos = "'MEI'"; // fallback literal
            }
            $colTipoJog  = hasColumn($pdo, 'jogadores', 'tipo') ? 'j.tipo' : (hasColumn($pdo, 'jogadores', 'era') ? 'j.era' : 'NULL');
            $colTipoTime = hasColumn($pdo, 'times', 'tipo')     ? 't.tipo' : ($hasEraT ? 't.era' : 'NULL');

            $jogs = $pdo->query("
                SELECT j.id, j.nome, $colPos AS pos_raw, j.rating, j.time_id,
                       COALESCE($colTipoJog, $colTipoTime, 'GERAL') AS tipo,
                       t.nome AS time_nome, $colSiglaJoin
                FROM jogadores j
                JOIN times t ON t.id = j.time_id
                ORDER BY j.rating DESC, j.nome ASC
            ")->fetchAll();

            $combos = [];
            foreach ($jogs as &$j) {
                $raw = trim((string)($j['pos_raw'] ?? ''));
                $parts = preg_split('/[\/,\-\|]+/u', $raw);
                $posicoes = [];
                foreach ($parts as $p) {
                    $p = strtoupper(trim($p));
                    if ($p !== '') $posicoes[$p] = true;
                }
                if (!$posicoes) $posicoes['MEI'] = true;
                $j['posicoes']   = array_keys($posicoes);
                $j['posicao']    = $j['posicoes'][0];
                $j['rating']     = intval($j['rating'] ?? 0);
                $j['decada']     = trim((string)($j['tipo'] ?? 'GERAL'));
                $j['nome_base']  = nomeBase((string)$j['nome']);
                unset($j['pos_raw']);

                foreach ($j['posicoes'] as $pos) {
                    $chave = intval($j['time_id']) . '_' . $j['decada'];
                    if (!isset($combos[$pos]))        $combos[$pos] = [];
                    if (!isset($combos[$pos][$chave])) {
                        $combos[$pos][$chave] = [
                            'time_id'   => intval($j['time_id']),
                            'sigla'     => $j['sigla'],
                            'time_nome' => $j['time_nome'],
                            'decada'    => $j['decada'],
                        ];
                    }
                }
            }
            unset($j);

            $combosOut = [];
            foreach ($combos as $pos => $lista) $combosOut[$pos] = array_values($lista);

            $out = json_encode(['times' => $times, 'jogadores' => $jogs, 'combos' => $combosOut], JSON_UNESCAPED_UNICODE);
            if ($out === false) throw new RuntimeException('Erro ao serializar dados: ' . json_last_error_msg());
            echo $out;

        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode(['erro' => 'Erro ao carregar dados: ' . $e->getMessage()]);
        }
        break;

    case 'salvar_ranking':
        $body = json_decode(file_get_contents('php://input'), true);
        $usuario = substr(trim($body['usuario'] ?? 'Anonimo'), 0, 100);
        $pontos  = intval($body['pontos'] ?? 0);
        $time_id = intval($body['time_id'] ?? 0);
        $decada  = substr(trim((string)($body['decada'] ?? '')), 0, 40);

        if (!$pontos || !$time_id) {
            http_response_code(400);
            echo json_encode(['erro' => 'Dados incompletos']);
            break;
        }

        $temDecada = hasColumn($pdo, 'rankings', 'decada_sorteada');
        if ($temDecada) {
            $stmt = $pdo->prepare("INSERT INTO rankings (usuario, pontos, time_sorteado, decada_sorteada) VALUES (?, ?, ?, ?)");
            $stmt->execute([$usuario, $pontos, $time_id, $decada ?: null]);
        } else {
            $stmt = $pdo->prepare("INSERT INTO rankings (usuario, pontos, time_sorteado) VALUES (?, ?, ?)");
            $stmt->execute([$usuario, $pontos, $time_id]);
        }
        echo json_encode(['sucesso' => true, 'id' => $pdo->lastInsertId()]);
        break;

    case 'ranking':
        $temDecada    = hasColumn($pdo, 'rankings', 'decada_sorteada');
        $hasSiglaRk   = hasColumn($pdo, 'times', 'sigla');
        $colSiglaRk   = $hasSiglaRk ? 't.sigla' : "UPPER(SUBSTRING(t.nome,1,4)) AS sigla";
        $sql = "
            SELECT r.usuario, r.pontos, r.criado_em,
                   t.nome AS time_nome, $colSiglaRk" . ($temDecada ? ", r.decada_sorteada" : "") . "
            FROM rankings r
            JOIN times t ON t.id = r.time_sorteado
            ORDER BY r.pontos DESC, r.criado_em ASC
            LIMIT 20
        ";
        echo json_encode($pdo->query($sql)->fetchAll());
        break;

    case 'ranking_global':
        if (!iniciarModuloConta($pdo)) break;
        $sql = "
            SELECT u.usuario, u.nome_time, u.escudo,
                   COUNT(p.id) AS jogos,
                   SUM(p.campeao) AS titulos,
                   MAX(p.pontos) AS melhor_pontos,
                   MAX(p.ovr) AS melhor_ovr
            FROM usuarios u
            JOIN partidas_usuario p ON p.usuario_id = u.id
            GROUP BY u.id
            ORDER BY titulos DESC, melhor_pontos DESC
            LIMIT 50
        ";
        try {
            $rows = $pdo->query($sql)->fetchAll();
        } catch (Throwable $e) {
            $rows = [];
        }
        echo json_encode($rows);
        break;


    // ================================================================
    // MÓDULO: PONTOS / LIGAS
    // ================================================================
    case 'perfil':
        if (!iniciarModuloConta($pdo)) break;
        $u = usuarioLogado($pdo);
        if (!$u) { http_response_code(401); echo json_encode(['erro'=>'Nao autenticado']); break; }
        ensurePontosTabelas($pdo);
        $uid = intval($u['id']);

        // Pontos totais
        $pts = $pdo->prepare("SELECT total_pontos FROM usuario_pontos WHERE usuario_id=? LIMIT 1");
        $pts->execute([$uid]);
        $ptRow = $pts->fetch();
        $totalPts = $ptRow ? intval($ptRow['total_pontos']) : 0;

        // Conquistas desbloqueadas
        $cq = $pdo->prepare("SELECT conquista_id, desbloqueada_em FROM usuario_conquistas WHERE usuario_id=? ORDER BY desbloqueada_em DESC");
        $cq->execute([$uid]);
        $conquistas = $cq->fetchAll();

        // Stats gerais
        $st = $pdo->prepare("SELECT COUNT(*) AS jogos, SUM(campeao) AS titulos, MAX(ovr) AS melhor_ovr FROM partidas_usuario WHERE usuario_id=?");
        $st->execute([$uid]);
        $stats = $st->fetch();

        echo json_encode([
            'usuario'    => $u['usuario'],
            'nome_time'  => $u['nome_time'],
            'escudo'     => $u['escudo'],
            'pontos'     => $totalPts,
            'liga'       => ligaDosPontos($totalPts),
            'conquistas' => $conquistas,
            'stats'      => $stats,
        ]);
        break;

    case 'ranking_ligas':
        if (!iniciarModuloConta($pdo)) break;
        ensurePontosTabelas($pdo);
        try {
            $rows = $pdo->query("
                SELECT u.usuario, u.nome_time, u.escudo,
                       COALESCE(up.total_pontos,0) AS pontos,
                       COUNT(p.id) AS jogos,
                       COALESCE(SUM(p.campeao),0) AS titulos
                FROM usuarios u
                LEFT JOIN usuario_pontos up ON up.usuario_id=u.id
                LEFT JOIN partidas_usuario p ON p.usuario_id=u.id
                GROUP BY u.id, u.usuario, u.nome_time, u.escudo, up.total_pontos
                ORDER BY pontos DESC, titulos DESC
                LIMIT 100
            ")->fetchAll();
            // Adiciona liga em cada linha
            foreach ($rows as &$r) {
                $r['liga'] = ligaDosPontos(intval($r['pontos']));
                $r['pontos'] = intval($r['pontos']);
            }
            echo json_encode($rows);
        } catch (Throwable $e) { echo json_encode([]); }
        break;

    case 'adicionar_pontos':
        // Chamado internamente (pelo salvar_partida e duelo_resultado)
        // Não exposto diretamente — protegido por sessão
        if (!iniciarModuloConta($pdo)) break;
        $u = usuarioLogado($pdo);
        if (!$u) { http_response_code(401); echo json_encode(['erro'=>'Nao autenticado']); break; }
        $body = json_decode(file_get_contents('php://input'), true);
        $qtd = intval($body['pontos'] ?? 0);
        $motivo = substr(trim($body['motivo'] ?? ''), 0, 100);
        if ($qtd <= 0) { echo json_encode(['sucesso'=>false]); break; }
        ensurePontosTabelas($pdo);
        adicionarPontos($pdo, intval($u['id']), $qtd, $motivo);
        $total = $pdo->prepare("SELECT total_pontos FROM usuario_pontos WHERE usuario_id=?");
        $total->execute([intval($u['id'])]);
        $r = $total->fetch();
        echo json_encode(['sucesso'=>true,'total'=>intval($r['total_pontos']??0),'liga'=>ligaDosPontos(intval($r['total_pontos']??0))]);
        break;

    // ================================================================
    // MÓDULO: CONQUISTAS
    // ================================================================
    case 'verificar_conquistas':
        if (!iniciarModuloConta($pdo)) break;
        $u = usuarioLogado($pdo);
        if (!$u) { http_response_code(401); echo json_encode(['erro'=>'Nao autenticado']); break; }
        $body = json_decode(file_get_contents('php://input'), true);
        // Recebe o contexto da partida
        $ctx = $body['ctx'] ?? [];
        ensurePontosTabelas($pdo);
        $uid = intval($u['id']);

        // Conquistas já desbloqueadas
        $jaTem = $pdo->prepare("SELECT conquista_id FROM usuario_conquistas WHERE usuario_id=?");
        $jaTem->execute([$uid]);
        $desbloqueadas = array_column($jaTem->fetchAll(), 'conquista_id');

        $novas = [];
        $ptsGanhos = 0;
        foreach (CONQUISTAS_DEF as $id => $def) {
            if (in_array($id, $desbloqueadas)) continue;
            // Verifica condição
            $cumprida = false;
            switch ($id) {
                case 'primeiro_titulo':    $cumprida = !empty($ctx['campeao']); break;
                case 'rei_brasil':         $cumprida = !empty($ctx['campeao']) && !empty($ctx['time_brasileiro']); break;
                case 'underdog':           $cumprida = !empty($ctx['campeao']) && intval($ctx['ovr']??99)<=83; break;
                case 'lendario':           $cumprida = !empty($ctx['campeao']) && intval($ctx['ovr']??99)<=78; break;
                case 'lenda_viva':         $cumprida = !empty($ctx['tem_pele_atacante']); break;
                case 'los_galacticos':     $cumprida = !empty($ctx['tem_messi']) && !empty($ctx['tem_cr7']) && !empty($ctx['tem_neymar']); break;
                case 'trio_brasileiro':    $cumprida = !empty($ctx['tem_neymar']) && !empty($ctx['tem_ronaldo_brasil']) && !empty($ctx['tem_pele_atacante']); break;
                case 'invicto':            $cumprida = !empty($ctx['campeao']) && intval($ctx['derrotas']??1)===0 && intval($ctx['empates']??1)===0; break;
                case 'sem_sofrer':         $cumprida = !empty($ctx['campeao']) && intval($ctx['gols_sofridos']??99)===0; break;
                case 'muralha':            $cumprida = !empty($ctx['campeao']) && intval($ctx['gols_sofridos']??99)<=3; break;
                case 'goleador':           $cumprida = intval($ctx['gols_marcados']??0)>=20; break;
                case 'virada_penaltis':    $cumprida = !empty($ctx['venceu_penaltis']); break;
                case 'campeao_defensivo':  $cumprida = !empty($ctx['campeao']) && ($ctx['mentalidade']??'')===('defensivo'); break;
                case 'campeao_ofensivo':   $cumprida = !empty($ctx['campeao']) && ($ctx['mentalidade']??'')===('ofensivo'); break;
                case 'goleada_historica':  $cumprida = intval($ctx['maior_goleada']??0)>=5; break;
                case 'equilibrista':       $cumprida = !empty($ctx['campeao']) && !empty($ctx['times_diferentes']); break;
                case 'hat_trick_titulos':  // 3 títulos acumulados
                    $t3 = $pdo->prepare("SELECT COUNT(*) FROM partidas_usuario WHERE usuario_id=? AND campeao=1");
                    $t3->execute([$uid]);
                    $cumprida = intval($t3->fetchColumn()) >= 3;
                    break;
                case 'veterano':           // 10 partidas
                    $v = $pdo->prepare("SELECT COUNT(*) FROM partidas_usuario WHERE usuario_id=?");
                    $v->execute([$uid]);
                    $cumprida = intval($v->fetchColumn()) >= 10;
                    break;
                case 'duelo_vitorioso':    $cumprida = !empty($ctx['ganhou_duelo']); break;
                case 'campeao_diario':     $cumprida = !empty($ctx['ganhou_diario']); break;
            }
            if ($cumprida) {
                $ins = $pdo->prepare("INSERT IGNORE INTO usuario_conquistas (usuario_id, conquista_id) VALUES (?,?)");
                $ins->execute([$uid, $id]);
                $novas[] = $id;
                $ptsGanhos += $def['pontos'];
            }
        }
        if ($ptsGanhos > 0) adicionarPontos($pdo, $uid, $ptsGanhos, 'conquistas_'.implode(',',$novas));
        echo json_encode(['novas'=>$novas,'pontos_ganhos'=>$ptsGanhos]);
        break;

    // ================================================================
    // MÓDULO: DUELOS MULTIPLAYER
    // ================================================================
    case 'duelo_criar':
        if (!iniciarModuloConta($pdo)) break;
        $u = usuarioLogado($pdo);
        if (!$u) { http_response_code(401); echo json_encode(['erro'=>'Nao autenticado']); break; }
        $body = json_decode(file_get_contents('php://input'), true);
        $escalacao = json_encode($body['escalacao'] ?? [], JSON_UNESCAPED_UNICODE);
        $ovr = intval($body['ovr'] ?? 0);
        $formacao = substr(trim($body['formacao'] ?? '433'), 0, 10);
        $mentalidade = substr(trim($body['mentalidade'] ?? 'equilibrado'), 0, 20);
        $nome_time = substr(trim($body['nome_time'] ?? $u['nome_time']), 0, 80);
        ensurePontosTabelas($pdo);
        // Gera código único de 6 chars
        do {
            $codigo = strtoupper(substr(str_replace(['0','O','I','1','L'],['A','B','C','D','E'], base_convert(rand(1000000,9999999), 10, 36)), 0, 6));
            $chk = $pdo->prepare("SELECT id FROM duelos WHERE codigo=? LIMIT 1");
            $chk->execute([$codigo]);
        } while ($chk->fetch());
        $st = $pdo->prepare("INSERT INTO duelos (codigo, criador_id, criador_nome, criador_time, criador_ovr, criador_escalacao, criador_formacao, criador_mentalidade, status) VALUES (?,?,?,?,?,?,?,?,'aguardando')");
        $st->execute([$codigo, intval($u['id']), $u['usuario'], $nome_time, $ovr, $escalacao, $formacao, $mentalidade]);
        echo json_encode(['sucesso'=>true,'codigo'=>$codigo]);
        break;

    case 'duelo_entrar':
        if (!iniciarModuloConta($pdo)) break;
        $u = usuarioLogado($pdo);
        if (!$u) { http_response_code(401); echo json_encode(['erro'=>'Nao autenticado']); break; }
        $body = json_decode(file_get_contents('php://input'), true);
        $codigo = strtoupper(preg_replace('/[^A-Z0-9]/', '', $body['codigo'] ?? ''));
        ensurePontosTabelas($pdo);
        $duelo = $pdo->prepare("SELECT * FROM duelos WHERE codigo=? LIMIT 1");
        $duelo->execute([$codigo]);
        $d = $duelo->fetch();
        if (!$d) { http_response_code(404); echo json_encode(['erro'=>'Duelo não encontrado']); break; }
        if ($d['status'] !== 'aguardando') { echo json_encode(['erro'=>'Duelo já encerrado','duelo'=>$d]); break; }
        if ($d['criador_id'] == $u['id']) { echo json_encode(['erro'=>'Você criou este duelo']); break; }
        // Retorna dados do duelo para o desafiante montar o time
        echo json_encode([
            'sucesso'      => true,
            'codigo'       => $codigo,
            'adversario'   => $d['criador_nome'],
            'adv_time'     => $d['criador_time'],
            'adv_ovr'      => intval($d['criador_ovr']),
            'adv_formacao' => $d['criador_formacao'],
        ]);
        break;

    case 'duelo_resolver':
        if (!iniciarModuloConta($pdo)) break;
        $u = usuarioLogado($pdo);
        if (!$u) { http_response_code(401); echo json_encode(['erro'=>'Nao autenticado']); break; }
        $body = json_decode(file_get_contents('php://input'), true);
        $codigo = strtoupper(preg_replace('/[^A-Z0-9]/', '', $body['codigo'] ?? ''));
        $escalacao2 = json_encode($body['escalacao'] ?? [], JSON_UNESCAPED_UNICODE);
        $ovr2 = intval($body['ovr'] ?? 0);
        $formacao2 = substr(trim($body['formacao'] ?? '433'), 0, 10);
        $mentalidade2 = substr(trim($body['mentalidade'] ?? 'equilibrado'), 0, 20);
        $nome2 = substr(trim($body['nome_time'] ?? $u['nome_time']), 0, 80);
        ensurePontosTabelas($pdo);
        $duelo = $pdo->prepare("SELECT * FROM duelos WHERE codigo=? AND status='aguardando' LIMIT 1");
        $duelo->execute([$codigo]);
        $d = $duelo->fetch();
        if (!$d) { http_response_code(404); echo json_encode(['erro'=>'Duelo inválido ou já encerrado']); break; }
        if ($d['criador_id'] == $u['id']) { echo json_encode(['erro'=>'Você não pode jogar contra si mesmo']); break; }

        // Simula o jogo (lógica Poisson simples aqui no PHP)
        $ovr1 = intval($d['criador_ovr']);
        $diff = $ovr1 - $ovr2;
        $base1 = 1.3 + $diff * 0.032;
        $base2 = 1.3 - $diff * 0.032;
        $g1 = max(0, poissonSample(max(0.15, $base1)));
        $g2 = max(0, poissonSample(max(0.15, $base2)));
        // Pênaltis se empate
        $pen1 = 0; $pen2 = 0; $pen = false;
        if ($g1 === $g2) {
            $pen = true;
            [$pen1, $pen2] = resolverPenaltis($ovr1, $ovr2);
        }
        $criadorGanhou = $g1 > $g2 || ($pen && $pen1 > $pen2);
        $empate = !$pen && $g1 === $g2;
        $placar = "$g1-$g2".($pen?" ($pen1-{$pen2}p)":'');

        // Atualiza duelo
        $up = $pdo->prepare("UPDATE duelos SET desafiante_id=?, desafiante_nome=?, desafiante_time=?, desafiante_ovr=?, desafiante_escalacao=?, desafiante_formacao=?, desafiante_mentalidade=?, gols1=?, gols2=?, pen1=?, pen2=?, status='encerrado', encerrado_em=NOW() WHERE codigo=?");
        $up->execute([intval($u['id']), $u['usuario'], $nome2, $ovr2, $escalacao2, $formacao2, $mentalidade2, $g1, $g2, $pen1, $pen2, $codigo]);

        // Distribui pontos
        if (!$empate) {
            $vencedor_id = $criadorGanhou ? $d['criador_id'] : $u['id'];
            $perdedor_id = $criadorGanhou ? $u['id'] : $d['criador_id'];
            adicionarPontos($pdo, $vencedor_id, 80, 'duelo_vitoria');
            adicionarPontos($pdo, $perdedor_id, 20, 'duelo_derrota');
        } else {
            adicionarPontos($pdo, $d['criador_id'], 40, 'duelo_empate');
            adicionarPontos($pdo, intval($u['id']), 40, 'duelo_empate');
        }

        echo json_encode([
            'sucesso'       => true,
            'placar'        => $placar,
            'g1'            => $g1, 'g2' => $g2,
            'pen'           => $pen, 'pen1' => $pen1, 'pen2' => $pen2,
            'criador_ganhou'=> $criadorGanhou,
            'empate'        => $empate,
            'criador_nome'  => $d['criador_nome'],
            'criador_time'  => $d['criador_time'],
            'criador_ovr'   => $ovr1,
            'desafiante_nome'=> $u['usuario'],
            'desafiante_time'=> $nome2,
        ]);
        break;

    case 'duelo_status':
        $codigo = strtoupper(preg_replace('/[^A-Z0-9]/', '', $_GET['codigo'] ?? ''));
        if (!$codigo) { http_response_code(400); echo json_encode(['erro'=>'Codigo obrigatorio']); break; }
        ensurePontosTabelas($pdo);
        $d = $pdo->prepare("SELECT codigo,criador_nome,criador_time,criador_ovr,desafiante_nome,desafiante_time,desafiante_ovr,gols1,gols2,pen1,pen2,status,encerrado_em FROM duelos WHERE codigo=? LIMIT 1");
        $d->execute([$codigo]);
        $row = $d->fetch();
        if (!$row) { http_response_code(404); echo json_encode(['erro'=>'Nao encontrado']); break; }
        echo json_encode($row);
        break;

    case 'duelos_recentes':
        if (!iniciarModuloConta($pdo)) break;
        $u = usuarioLogado($pdo);
        if (!$u) { http_response_code(401); echo json_encode(['erro'=>'Nao autenticado']); break; }
        ensurePontosTabelas($pdo);
        $uid = intval($u['id']);
        $rows = $pdo->prepare("SELECT codigo, criador_nome, criador_time, criador_ovr, desafiante_nome, desafiante_time, desafiante_ovr, gols1, gols2, pen1, pen2, status, criado_em FROM duelos WHERE criador_id=? OR desafiante_id=? ORDER BY criado_em DESC LIMIT 10");
        $rows->execute([$uid, $uid]);
        echo json_encode($rows->fetchAll());
        break;

    default:
        http_response_code(404);
        echo json_encode(['erro' => 'Acao invalida']);
}

// ================================================================
// FUNÇÕES AUXILIARES — Pontos, Ligas, Conquistas
// ================================================================
function ensurePontosTabelas(PDO $pdo): void {
    $pdo->exec("CREATE TABLE IF NOT EXISTS usuario_pontos (
        usuario_id INT PRIMARY KEY,
        total_pontos INT NOT NULL DEFAULT 0,
        atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        CONSTRAINT fk_up_usuario FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $pdo->exec("CREATE TABLE IF NOT EXISTS usuario_conquistas (
        usuario_id INT NOT NULL,
        conquista_id VARCHAR(50) NOT NULL,
        desbloqueada_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (usuario_id, conquista_id),
        CONSTRAINT fk_uc_usuario FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $pdo->exec("CREATE TABLE IF NOT EXISTS duelos (
        id INT AUTO_INCREMENT PRIMARY KEY,
        codigo CHAR(6) NOT NULL UNIQUE,
        criador_id INT NOT NULL,
        criador_nome VARCHAR(80) NOT NULL,
        criador_time VARCHAR(80) NOT NULL,
        criador_ovr TINYINT NOT NULL DEFAULT 0,
        criador_escalacao LONGTEXT NULL,
        criador_formacao VARCHAR(10) NOT NULL DEFAULT '433',
        criador_mentalidade VARCHAR(20) NOT NULL DEFAULT 'equilibrado',
        desafiante_id INT NULL,
        desafiante_nome VARCHAR(80) NULL,
        desafiante_time VARCHAR(80) NULL,
        desafiante_ovr TINYINT NULL,
        desafiante_escalacao LONGTEXT NULL,
        desafiante_formacao VARCHAR(10) NULL,
        desafiante_mentalidade VARCHAR(20) NULL,
        gols1 TINYINT NULL,
        gols2 TINYINT NULL,
        pen1 TINYINT NULL DEFAULT 0,
        pen2 TINYINT NULL DEFAULT 0,
        status ENUM('aguardando','encerrado') NOT NULL DEFAULT 'aguardando',
        criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        encerrado_em TIMESTAMP NULL,
        INDEX idx_codigo (codigo),
        INDEX idx_criador (criador_id),
        INDEX idx_desafiante (desafiante_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}

function adicionarPontos(PDO $pdo, int $uid, int $qtd, string $motivo): void {
    $pdo->prepare("INSERT INTO usuario_pontos (usuario_id, total_pontos) VALUES (?,?) ON DUPLICATE KEY UPDATE total_pontos=total_pontos+?")
        ->execute([$uid, $qtd, $qtd]);
}

function ligaDosPontos(int $pts): array {
    $ligas = [
        ['id'=>'elite',    'nome'=>'Copa433 Elite', 'icone'=>'👑', 'min'=>25000],
        ['id'=>'diamante', 'nome'=>'Diamante',      'icone'=>'💠', 'min'=>10000],
        ['id'=>'platina',  'nome'=>'Platina',        'icone'=>'💎', 'min'=>4000],
        ['id'=>'ouro',     'nome'=>'Ouro',           'icone'=>'🥇', 'min'=>1500],
        ['id'=>'prata',    'nome'=>'Prata',          'icone'=>'🥈', 'min'=>500],
        ['id'=>'bronze',   'nome'=>'Bronze',         'icone'=>'🥉', 'min'=>0],
    ];
    foreach ($ligas as $l) { if ($pts >= $l['min']) return $l; }
    return $ligas[5];
}

function poissonSample(float $lambda): int {
    $L = exp(-$lambda); $k = 0; $p = 1.0;
    do { $k++; $p *= (float)(mt_rand(1,PHP_INT_MAX)/PHP_INT_MAX); } while ($p > $L);
    return $k - 1;
}

function resolverPenaltis(int $ovr1, int $ovr2): array {
    $c1 = min(0.92, max(0.5, 0.7 + ($ovr1-$ovr2)*0.006));
    $c2 = min(0.92, max(0.5, 0.7 - ($ovr1-$ovr2)*0.006));
    $p1=0; $p2=0;
    for($i=0;$i<5;$i++){ if(mt_rand()/PHP_INT_MAX<$c1)$p1++; if(mt_rand()/PHP_INT_MAX<$c2)$p2++; }
    while($p1===$p2){ if(mt_rand()/PHP_INT_MAX<$c1)$p1++; if(mt_rand()/PHP_INT_MAX<$c2)$p2++; }
    return [$p1,$p2];
}

// Definição de todas as conquistas
const CONQUISTAS_DEF = [
    'primeiro_titulo'   =>['nome'=>'Primeiro Título',     'icone'=>'🏆','desc'=>'Ganhe a Copa433 pela primeira vez.',             'pontos'=>20, 'raridade'=>'comum'],
    'rei_brasil'        =>['nome'=>'Rei do Brasil',       'icone'=>'🇧🇷','desc'=>'Seja campeão com um time 100% brasileiro.',       'pontos'=>30, 'raridade'=>'raro'],
    'underdog'          =>['nome'=>'Underdog',            'icone'=>'🐶','desc'=>'Ganhe com OVR médio ≤83.',                        'pontos'=>50, 'raridade'=>'epico'],
    'lendario'          =>['nome'=>'Lendário',            'icone'=>'⚡','desc'=>'Ganhe com OVR médio ≤78.',                        'pontos'=>100,'raridade'=>'lendario'],
    'lenda_viva'        =>['nome'=>'Lenda Viva',          'icone'=>'👑','desc'=>'Escale Pelé como atacante.',                      'pontos'=>20, 'raridade'=>'comum'],
    'los_galacticos'    =>['nome'=>'Los Galácticos',      'icone'=>'⭐','desc'=>'Messi + Cristiano Ronaldo + Neymar no mesmo XI.', 'pontos'=>75, 'raridade'=>'epico'],
    'trio_brasileiro'   =>['nome'=>'Trio Ouro Verde',     'icone'=>'🟢','desc'=>'Pelé + Ronaldo (Brasil) + Neymar no mesmo XI.',  'pontos'=>60, 'raridade'=>'raro'],
    'invicto'           =>['nome'=>'Invicto',             'icone'=>'🛡️','desc'=>'Campeão sem nenhuma derrota ou empate.',         'pontos'=>60, 'raridade'=>'epico'],
    'sem_sofrer'        =>['nome'=>'Muralha Absoluta',    'icone'=>'🧱','desc'=>'Campeão sem sofrer nenhum gol.',                 'pontos'=>80, 'raridade'=>'lendario'],
    'muralha'           =>['nome'=>'Sólido',              'icone'=>'🔒','desc'=>'Campeão sofrendo ≤3 gols no torneio.',           'pontos'=>40, 'raridade'=>'raro'],
    'goleador'          =>['nome'=>'Artilheiro',          'icone'=>'⚽','desc'=>'Marque 20+ gols em um torneio.',                 'pontos'=>30, 'raridade'=>'comum'],
    'virada_penaltis'   =>['nome'=>'Drama Puro',          'icone'=>'🎭','desc'=>'Classifique-se em pênaltis.',                    'pontos'=>25, 'raridade'=>'comum'],
    'campeao_defensivo' =>['nome'=>'Mourinho Mode',       'icone'=>'🧱','desc'=>'Campeão com mentalidade Defensiva.',              'pontos'=>35, 'raridade'=>'raro'],
    'campeao_ofensivo'  =>['nome'=>'Jogo Bonito',         'icone'=>'🎨','desc'=>'Campeão com mentalidade Ofensiva.',              'pontos'=>35, 'raridade'=>'raro'],
    'goleada_historica' =>['nome'=>'Goleada Histórica',   'icone'=>'💥','desc'=>'Vença por 5+ gols de diferença.',                'pontos'=>30, 'raridade'=>'comum'],
    'equilibrista'      =>['nome'=>'Diversidade',         'icone'=>'🌍','desc'=>'Campeão com jogadores de 5+ eras diferentes.',   'pontos'=>45, 'raridade'=>'raro'],
    'hat_trick_titulos' =>['nome'=>'Hat-trick',           'icone'=>'🎩','desc'=>'Ganhe a Copa433 3 vezes.',                       'pontos'=>75, 'raridade'=>'epico'],
    'veterano'          =>['nome'=>'Veterano',            'icone'=>'📅','desc'=>'Jogue 10 partidas.',                             'pontos'=>25, 'raridade'=>'comum'],
    'duelo_vitorioso'   =>['nome'=>'Caça-Duelos',         'icone'=>'⚔️','desc'=>'Vença seu primeiro duelo multiplayer.',          'pontos'=>40, 'raridade'=>'raro'],
    'campeao_diario'    =>['nome'=>'Rei do Dia',          'icone'=>'📅','desc'=>'Seja campeão no Desafio Diário.',                'pontos'=>50, 'raridade'=>'epico'],
];
