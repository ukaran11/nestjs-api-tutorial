import { Injectable } from "@nestjs/common";
import * as argon from 'argon2';
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: AuthDto) {
    // generate the password hash
    const hash = await argon.hash(dto.password);
    
    // save the new user in the db
    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        hash
      }
    })
    delete user.hash;
    return user;
  }

  signin(dto) {
    return { msg: 'I have signed in'};
  }
}