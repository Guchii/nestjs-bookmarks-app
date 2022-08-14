import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService) {
    console.log(jwt);
  }
  async register(dto: AuthDto) {
    const hashedPassword = await argon.hash(dto.password);
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          password: hashedPassword,
        },
      });
      delete user.password;
      return user;
    } catch (e) {
      if (e instanceof PrismaClientKnownRequestError) {
        if (e.code === 'P2002') {
          throw new ForbiddenException('User already exists');
        }
      }
    }
  }

  async login(dto: AuthDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) {
      throw new ForbiddenException('User not found');
    }
    const isValid = await argon.verify(user.password, dto.password);
    if (!isValid) {
      throw new ForbiddenException('Invalid credentials');
    }
    delete user.password;
    return this.signToken(user.id);
  }
  async signToken(userId: number): Promise<{ access_token: string }> {
    const data = { userId };
    const access_token = await this.jwt.signAsync(data);
    return { access_token };
  }
}
