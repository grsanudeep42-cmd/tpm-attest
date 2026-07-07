#!/usr/bin/env python3
"""
VOID SECTOR — A 2-D space shooter gated by TPM-Attest hardware attestation.

Pipeline:
  game.py  ──ctypes──▶  libeos_sdk.so  ──(LD_PRELOAD)──▶  eac_hook.so
           ◀──socket──  shim.py        ──HTTP──▶  TPM attestation server

Run via:  ./run_game.sh   (handles LD_PRELOAD automatically)
"""

import math, random, sys, os, time
import pygame
try:
    from .eos_bridge import begin_attestation, get_result   # package run
except ImportError:
    from eos_bridge import begin_attestation, get_result    # direct run

# ── constants ────────────────────────────────────────────────────────────────
W, H       = 1024, 768
FPS        = 60
TITLE      = "VOID SECTOR  //  TPM-Attest Demo"

# colours
BLACK   = (0,   0,   0)
WHITE   = (255, 255, 255)
CYAN    = (0,   220, 255)
RED     = (255, 50,  50)
GREEN   = (50,  255, 120)
YELLOW  = (255, 220, 0)
ORANGE  = (255, 140, 0)
PURPLE  = (160, 0,   255)
GREY    = (80,  80,  100)
DKBLUE  = (5,   10,  30)
TEAL    = (0,   180, 180)

pygame.init()
screen = pygame.display.set_mode((W, H))
pygame.display.set_caption(TITLE)
clock  = pygame.time.Clock()

# ── fonts ────────────────────────────────────────────────────────────────────
F_BIG   = pygame.font.SysFont("monospace", 52, bold=True)
F_MED   = pygame.font.SysFont("monospace", 28, bold=True)
F_SM    = pygame.font.SysFont("monospace", 18)
F_TINY  = pygame.font.SysFont("monospace", 14)

# ── star field ───────────────────────────────────────────────────────────────
STARS = [(random.randint(0, W), random.randint(0, H),
          random.uniform(0.3, 1.5), random.randint(100, 255))
         for _ in range(220)]


def draw_stars(surf, offset=0.0):
    for x, y, spd, br in STARS:
        yy = int((y + offset * spd) % H)
        c  = (br, br, br)
        surf.set_at((x, yy), c)


# ── drawing helpers ───────────────────────────────────────────────────────────
def text(surf, msg, font, colour, cx, cy, alpha=255):
    s = font.render(msg, True, colour)
    s.set_alpha(alpha)
    surf.blit(s, s.get_rect(center=(cx, cy)))


def draw_ship(surf, x, y, angle=0, colour=CYAN, scale=1.0):
    pts = [
        ( 0,  -20),
        (-12,  14),
        (  0,   8),
        ( 12,  14),
    ]
    rad = math.radians(angle)
    cos, sin = math.cos(rad), math.sin(rad)
    def rot(p):
        rx = p[0]*cos - p[1]*sin
        ry = p[0]*sin + p[1]*cos
        return (x + rx*scale, y + ry*scale)
    pygame.draw.polygon(surf, colour, [rot(p) for p in pts])
    pygame.draw.polygon(surf, WHITE,  [rot(p) for p in pts], 1)


def draw_enemy(surf, x, y, kind=0, r=18):
    if kind == 0:   # drone — diamond
        pts = [(x, y-r), (x+r, y), (x, y+r), (x-r, y)]
        pygame.draw.polygon(surf, RED,    pts)
        pygame.draw.polygon(surf, ORANGE, pts, 2)
    elif kind == 1: # cruiser — hexagon
        pts = [(x + r*math.cos(math.radians(60*i - 30)),
                y + r*math.sin(math.radians(60*i - 30))) for i in range(6)]
        pygame.draw.polygon(surf, PURPLE, pts)
        pygame.draw.polygon(surf, RED,    pts, 2)
    else:           # bomber — triangle
        pts = [(x, y-r), (x-r, y+r//2), (x+r, y+r//2)]
        pygame.draw.polygon(surf, ORANGE, pts)
        pygame.draw.polygon(surf, YELLOW, pts, 2)


def draw_explosion(surf, x, y, progress):
    """progress 0→1"""
    n = 12
    maxr = 50
    for i in range(n):
        angle = 2*math.pi*i/n + progress*2
        r     = maxr * progress
        bx    = x + r * math.cos(angle)
        by    = y + r * math.sin(angle)
        alpha = max(0, int(255*(1-progress)))
        size  = max(1, int(6*(1-progress)))
        colour = YELLOW if i%2==0 else ORANGE
        pygame.draw.circle(surf, colour, (int(bx), int(by)), size)


# ── game objects ──────────────────────────────────────────────────────────────
class Bullet:
    def __init__(self, x, y, vy=-10, colour=CYAN):
        self.x, self.y = float(x), float(y)
        self.vy = vy
        self.colour = colour
        self.alive = True

    def update(self):
        self.y += self.vy
        if self.y < -10 or self.y > H+10:
            self.alive = False

    def draw(self, surf):
        pygame.draw.rect(surf, self.colour,
                         (int(self.x)-2, int(self.y)-8, 4, 14))
        pygame.draw.rect(surf, WHITE,
                         (int(self.x)-1, int(self.y)-8, 2, 6))


class Enemy:
    SPEED_BASE = 1.4

    def __init__(self, wave=1):
        self.kind  = random.randint(0, 2)
        self.r     = [18, 22, 16][self.kind]
        self.x     = float(random.randint(self.r, W - self.r))
        self.y     = float(random.randint(-120, -self.r))
        spd        = self.SPEED_BASE + 0.25 * wave + random.uniform(-0.3, 0.5)
        self.vy    = max(0.8, spd)
        self.vx    = random.uniform(-0.6, 0.6)
        self.hp    = [1, 3, 2][self.kind]
        self.score = [100, 300, 200][self.kind]
        self.angle = 0.0
        self.shoot_cd = random.randint(60, 180)
        self.alive = True

    def update(self):
        self.x += self.vx
        self.y += self.vy
        self.angle += 1.5
        if self.x < self.r or self.x > W - self.r:
            self.vx *= -1
        if self.y > H + 40:
            self.alive = False
        self.shoot_cd -= 1

    def can_shoot(self):
        if self.shoot_cd <= 0:
            self.shoot_cd = random.randint(90, 200)
            return True
        return False

    def hit(self):
        self.hp -= 1
        if self.hp <= 0:
            self.alive = False
            return True
        return False

    def draw(self, surf):
        draw_enemy(surf, int(self.x), int(self.y), self.kind, self.r)
        # hp bar
        if self.hp > 1:
            bw = self.r * 2
            pygame.draw.rect(surf, GREY,
                             (int(self.x)-self.r, int(self.y)-self.r-8, bw, 5))
            ratio = self.hp / [1,3,2][self.kind]
            pygame.draw.rect(surf, GREEN,
                             (int(self.x)-self.r, int(self.y)-self.r-8, int(bw*ratio), 5))


class Explosion:
    def __init__(self, x, y):
        self.x, self.y = x, y
        self.t = 0.0
        self.alive = True

    def update(self):
        self.t += 0.04
        if self.t >= 1.0:
            self.alive = False

    def draw(self, surf):
        draw_explosion(surf, self.x, self.y, self.t)


class Player:
    def __init__(self):
        self.x     = float(W // 2)
        self.y     = float(H - 100)
        self.speed = 5.5
        self.hp    = 3
        self.max_hp= 3
        self.shoot_cd   = 0
        self.invincible = 0  # frames of invincibility after hit
        self.alive = True

    def update(self, keys):
        if keys[pygame.K_LEFT]  or keys[pygame.K_a]: self.x -= self.speed
        if keys[pygame.K_RIGHT] or keys[pygame.K_d]: self.x += self.speed
        if keys[pygame.K_UP]    or keys[pygame.K_w]: self.y -= self.speed
        if keys[pygame.K_DOWN]  or keys[pygame.K_s]: self.y += self.speed
        self.x = max(20, min(W-20, self.x))
        self.y = max(60, min(H-20, self.y))
        if self.shoot_cd > 0:
            self.shoot_cd -= 1
        if self.invincible > 0:
            self.invincible -= 1

    def try_shoot(self) -> list:
        if self.shoot_cd == 0:
            self.shoot_cd = 10
            return [Bullet(self.x, self.y - 20)]
        return []

    def hit(self):
        if self.invincible > 0:
            return
        self.hp -= 1
        self.invincible = 90
        if self.hp <= 0:
            self.alive = False

    def draw(self, surf):
        alpha = 255
        if self.invincible > 0 and (self.invincible // 6) % 2 == 0:
            alpha = 80
        # engine glow
        for i in range(3):
            r = random.randint(4, 10)
            cy = self.y + 14 + random.randint(0, 6)
            c  = random.choice([CYAN, TEAL, WHITE])
            s  = pygame.Surface((r*2, r*2), pygame.SRCALPHA)
            pygame.draw.circle(s, (*c, 120), (r,r), r)
            surf.blit(s, (int(self.x)-r, int(cy)-r))
        draw_ship(surf, int(self.x), int(self.y), colour=CYAN if alpha==255 else GREY)

    def draw_hud(self, surf, score, wave, highscore):
        # top bar background
        pygame.draw.rect(surf, (10,10,25), (0, 0, W, 44))
        pygame.draw.line(surf, CYAN, (0, 44), (W, 44), 1)
        # score
        text(surf, f"SCORE  {score:08d}", F_SM, CYAN,  120, 22)
        text(surf, f"HI     {highscore:08d}", F_SM, TEAL, 310, 22)
        text(surf, f"WAVE {wave}", F_SM, YELLOW, W//2, 22)
        # HP hearts
        for i in range(self.max_hp):
            c = RED if i < self.hp else GREY
            pygame.draw.circle(surf, c, (W-80 + i*28, 22), 10)
        text(surf, "HP", F_TINY, WHITE, W-100, 22)


# ── screens ───────────────────────────────────────────────────────────────────
def attest_screen(star_offset):
    """Show while TPM attestation is running."""
    result = get_result()
    dots   = int(time.time() * 2) % 4

    screen.fill(DKBLUE)
    draw_stars(screen, star_offset)

    # HUD frame
    bw, bh = 680, 360
    bx, by = W//2 - bw//2, H//2 - bh//2
    pygame.draw.rect(screen, (10,20,50), (bx, by, bw, bh), border_radius=12)
    pygame.draw.rect(screen, CYAN,      (bx, by, bw, bh), 2, border_radius=12)

    text(screen, "VOID SECTOR",     F_BIG, CYAN,   W//2, by+52)
    text(screen, "TPM-ATTEST SECURITY GATEWAY", F_SM, TEAL, W//2, by+90)
    pygame.draw.line(screen, CYAN, (bx+30, by+108), (bx+bw-30, by+108), 1)

    if not result["done"]:
        # spinner
        t   = time.time()
        cx, cy = W//2, by + 200
        for i in range(12):
            angle = 2*math.pi*i/12 - t*3
            r_in, r_out = 28, 42
            x1 = cx + r_in  * math.cos(angle)
            y1 = cy + r_in  * math.sin(angle)
            x2 = cx + r_out * math.cos(angle)
            y2 = cy + r_out * math.sin(angle)
            alpha = int(255 * ((i+1)/12))
            pygame.draw.line(screen, (*CYAN[:3], alpha), (x1,y1), (x2,y2), 3)

        status = "VERIFYING SYSTEM INTEGRITY" + "." * dots
        text(screen, status, F_SM, CYAN, W//2, by+260)

        steps = [
            "[ ✓ ]  Fetching challenge nonce ...",
            "[ ✓ ]  Reading PCR registers  (SHA-256 bank) ...",
            "[ ✓ ]  Building IMA Merkle tree ...",
            "[ ~ ]  Generating TPM Quote signature ...",
            "[ · ]  Posting attestation report to server ...",
        ]
        # animate which steps are shown based on time
        visible = min(5, int((time.time() % 15) / 3) + 1)
        for i, step in enumerate(steps[:visible]):
            col = GREEN if i < visible - 1 else YELLOW
            text(screen, step, F_TINY, col, W//2, by + 295 + i*22)

        text(screen, "Do not close this window.", F_TINY, GREY, W//2, by+330)
    else:
        if result["valid"]:
            text(screen, "[ ATTESTATION PASSED ]", F_MED, GREEN, W//2, by+180)
            pygame.draw.rect(screen, GREEN, (bx+60, by+205, bw-120, 3))
            token = result.get("token","")[:32]
            text(screen, f"TOKEN: {token}{'...' if token else 'N/A'}", F_TINY, TEAL, W//2, by+230)
            text(screen, "Platform integrity verified by hardware TPM 2.0", F_SM, WHITE, W//2, by+270)
            text(screen, "Press  ENTER  to launch game", F_MED, YELLOW, W//2, by+320)
        else:
            reason = result.get("reason","unknown")
            text(screen, "[ ACCESS DENIED ]", F_BIG, RED, W//2, by+170)
            pygame.draw.rect(screen, RED, (bx+60, by+210, bw-120, 2))
            text(screen, "TPM attestation FAILED", F_MED, ORANGE, W//2, by+245)
            text(screen, f"Reason: {reason[:60]}", F_TINY, RED, W//2, by+278)
            text(screen, "System integrity could not be verified.", F_SM, GREY, W//2, by+308)
            text(screen, "Press  ESC  to exit", F_SM, GREY, W//2, by+340)

    pygame.display.flip()
    return result


def game_over_screen(score, highscore, star_offset, won=False):
    screen.fill(DKBLUE)
    draw_stars(screen, star_offset)
    c = YELLOW if won else RED
    text(screen, "MISSION COMPLETE" if won else "GAME OVER", F_BIG, c, W//2, H//2-100)
    text(screen, f"SCORE:  {score:08d}", F_MED, WHITE,  W//2, H//2-30)
    text(screen, f"HI:     {highscore:08d}", F_MED, CYAN, W//2, H//2+10)
    text(screen, "Press  R  to retry   |   ESC  to quit", F_SM, GREY, W//2, H//2+80)
    pygame.display.flip()


def main():
    highscore = 0
    star_off  = 0.0

    # ── attestation phase ────────────────────────────────────────────────────
    begin_attestation("void_sector_player")

    attesting = True
    while attesting:
        clock.tick(FPS)
        star_off += 0.4
        for ev in pygame.event.get():
            if ev.type == pygame.QUIT:
                pygame.quit(); sys.exit()
            if ev.type == pygame.KEYDOWN:
                r = get_result()
                if ev.key == pygame.K_ESCAPE:
                    pygame.quit(); sys.exit()
                if ev.key == pygame.K_RETURN and r["done"] and r["valid"]:
                    attesting = False
                if ev.key == pygame.K_RETURN and r["done"] and not r["valid"]:
                    pygame.quit(); sys.exit()

        result = attest_screen(star_off)
        if result["done"] and result["valid"]:
            # Auto-advance after 2 s
            pass  # wait for ENTER

    # ── game loop ────────────────────────────────────────────────────────────
    while True:
        score    = 0
        wave     = 1
        player   = Player()
        bullets  = []
        e_bullets= []
        enemies  = []
        explosions = []
        spawn_cd = 80
        enemies_killed = 0
        wave_target    = 8
        star_off2      = star_off
        running  = True

        while running:
            clock.tick(FPS)
            star_off2 += 0.6

            for ev in pygame.event.get():
                if ev.type == pygame.QUIT:
                    pygame.quit(); sys.exit()
                if ev.type == pygame.KEYDOWN:
                    if ev.key == pygame.K_ESCAPE:
                        pygame.quit(); sys.exit()

            keys = pygame.key.get_pressed()
            if player.alive:
                player.update(keys)
                if keys[pygame.K_SPACE] or keys[pygame.K_z]:
                    bullets += player.try_shoot()

            # spawn enemies
            spawn_cd -= 1
            if spawn_cd <= 0 and len(enemies) < 6 + wave:
                enemies.append(Enemy(wave))
                spawn_cd = max(20, 80 - wave*8)

            # update
            for b in bullets:    b.update()
            for b in e_bullets:  b.update()
            for e in enemies:
                e.update()
                if e.can_shoot():
                    e_bullets.append(Bullet(e.x, e.y+e.r, vy=5, colour=RED))
            for ex in explosions: ex.update()

            # collisions: player bullets vs enemies
            for b in bullets:
                if not b.alive: continue
                for e in enemies:
                    if not e.alive: continue
                    if abs(b.x-e.x)<e.r and abs(b.y-e.y)<e.r:
                        b.alive = False
                        if e.hit():
                            score += e.score
                            enemies_killed += 1
                            explosions.append(Explosion(e.x, e.y))

            # enemy bullets vs player
            if player.alive:
                for b in e_bullets:
                    if not b.alive: continue
                    if abs(b.x-player.x)<16 and abs(b.y-player.y)<16:
                        b.alive = False
                        player.hit()
                        if not player.alive:
                            explosions.append(Explosion(player.x, player.y))

                # enemy body vs player
                for e in enemies:
                    if not e.alive: continue
                    if abs(e.x-player.x)<e.r+14 and abs(e.y-player.y)<e.r+14:
                        player.hit()
                        e.alive = False
                        explosions.append(Explosion(e.x, e.y))

            # prune dead objects
            bullets   = [b for b in bullets   if b.alive]
            e_bullets = [b for b in e_bullets  if b.alive]
            enemies   = [e for e in enemies    if e.alive]
            explosions= [x for x in explosions if x.alive]

            # wave advance
            if enemies_killed >= wave_target:
                wave          += 1
                enemies_killed = 0
                wave_target   += 4

            # ── draw ──────────────────────────────────────────────────────────
            screen.fill(DKBLUE)
            draw_stars(screen, star_off2)

            for e  in enemies:    e.draw(screen)
            for b  in bullets:    b.draw(screen)
            for b  in e_bullets:  b.draw(screen)
            for ex in explosions: ex.draw(screen)
            if player.alive:
                player.draw(screen)

            highscore = max(highscore, score)
            player.draw_hud(screen, score, wave, highscore)

            # attestation badge (bottom-right)
            pygame.draw.rect(screen, (0,40,20), (W-210, H-32, 205, 28), border_radius=6)
            pygame.draw.rect(screen, GREEN,     (W-210, H-32, 205, 28), 1, border_radius=6)
            text(screen, "TPM-ATTEST  ✓  VERIFIED", F_TINY, GREEN, W-107, H-18)

            pygame.display.flip()

            if not player.alive:
                running = False

        # game over
        highscore = max(highscore, score)
        waiting = True
        while waiting:
            clock.tick(FPS)
            star_off2 += 0.4
            for ev in pygame.event.get():
                if ev.type == pygame.QUIT:
                    pygame.quit(); sys.exit()
                if ev.type == pygame.KEYDOWN:
                    if ev.key == pygame.K_ESCAPE:
                        pygame.quit(); sys.exit()
                    if ev.key == pygame.K_r:
                        waiting = False
            game_over_screen(score, highscore, star_off2)


if __name__ == "__main__":
    main()
