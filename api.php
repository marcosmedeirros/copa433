<?php
session_start();
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
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

    case 'salvar_partida':
        if (!iniciarModuloConta($pdo)) break;
        $u = usuarioLogado($pdo);
        if (!$u) {
            http_response_code(401);
            echo json_encode(['erro' => 'Nao autenticado']);
            break;
        }
        $body = json_decode(file_get_contents('php://input'), true);
        $campeao = !empty($body['campeao']) ? 1 : 0;
        $pontos = intval($body['pontos'] ?? 0);
        $ovr = intval($body['ovr'] ?? 0);
        $msg = substr(trim((string)($body['msg'] ?? '')), 0, 255);
        $timeNome = substr(trim((string)($body['time_nome'] ?? ($u['nome_time'] ?? 'Meu Time'))), 0, 80);
        $escalacao = json_encode(($body['escalacao'] ?? []), JSON_UNESCAPED_UNICODE);
        $st = $pdo->prepare("
            INSERT INTO partidas_usuario (usuario_id, campeao, pontos, msg, ovr, time_nome, escalacao_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ");
        $st->execute([intval($u['id']), $campeao, $pontos, $msg, $ovr, $timeNome ?: 'Meu Time', $escalacao]);
        echo json_encode(['sucesso' => true]);
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

    default:
        http_response_code(404);
        echo json_encode(['erro' => 'Acao invalida']);
}
